//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/guiapp"
)

const (
	csVRedraw = 0x0001
	csHRedraw = 0x0002

	wsOverlappedWindow = 0x00CF0000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsBorder           = 0x00800000
	wsVScroll          = 0x00200000
	wsTabStop          = 0x00010000

	esMultiline    = 0x0004
	esAutoVScroll  = 0x0040
	esAutoHScroll  = 0x0080
	esReadOnly     = 0x0800
	esWantReturn   = 0x1000
	lbsNotify      = 0x0001
	colorWindow    = 5
	defaultGUIFont = 17
	idcArrow       = 32512
	swShow         = 5

	wmCreate       = 0x0001
	wmDestroy      = 0x0002
	wmSize         = 0x0005
	wmClose        = 0x0010
	wmSetFont      = 0x0030
	wmCommand      = 0x0111
	wmExitSizeMove = 0x0232
	wmApp          = 0x8000

	emSetSel       = 0x00B1
	emReplaceSel   = 0x00C2
	emSetLimitText = 0x00C5

	lbAddString    = 0x0180
	lbResetContent = 0x0184
	lbGetCurSel    = 0x0188

	idRefresh    = 1001
	idDevices    = 1002
	idConnect    = 1003
	idDisconnect = 1004
	idOutput     = 1005
	idInput      = 1006
	idSend       = 1007

	bnClicked    = 0
	lbnSelChange = 1

	wmAppEvent = wmApp + 1

	maxTerminalDisplayChars = 1 << 20
	maxTerminalInputChars   = v1.MaxTerminalChunkBytes - 1
)

const windowClassName = "WeDecentLocalCoreWindow"

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procSetWindowTextW   = user32.NewProc("SetWindowTextW")
	procGetWindowTextW   = user32.NewProc("GetWindowTextW")
	procGetWindowTextLen = user32.NewProc("GetWindowTextLengthW")
	procMoveWindow       = user32.NewProc("MoveWindow")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procLoadCursorW      = user32.NewProc("LoadCursorW")
	procMessageBoxW      = user32.NewProc("MessageBoxW")

	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procGetStockObject   = gdi32.NewProc("GetStockObject")
)

type point struct {
	X int32
	Y int32
}

type msg struct {
	Hwnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type eventKind uint8

const (
	eventRefreshDone eventKind = iota + 1
	eventConnectDone
	eventDisconnectDone
	eventTerminalData
	eventTerminalClosed
	eventTerminalError
	eventSendDone
	eventResizeDone
	eventExitReady
)

type uiEvent struct {
	kind       eventKind
	message    string
	snapshot   guiapp.Snapshot
	connection v1.Connection
	data       []byte
	session    uint64
	ack        chan struct{}
}

type winApp struct {
	controller *guiapp.Controller

	hwnd       uintptr
	status     uintptr
	refresh    uintptr
	devicesBox uintptr
	connect    uintptr
	disconnect uintptr
	output     uintptr
	input      uintptr
	send       uintptr

	devices []v1.Device

	clientWidth  int
	clientHeight int

	busyRefresh    bool
	busyConnect    bool
	busyDisconnect bool
	busySend       bool
	closingApp     bool

	readCancel context.CancelFunc
	sessionSeq uint64

	eventMu   sync.Mutex
	nextEvent uintptr
	events    map[uintptr]uiEvent
	startErr  error
}

var activeApp *winApp

func runUI(controller *guiapp.Controller) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	app := &winApp{controller: controller, events: make(map[uintptr]uiEvent)}
	activeApp = app
	defer func() { activeApp = nil }()

	instance, _, err := procGetModuleHandleW.Call(0)
	if instance == 0 {
		return callError("GetModuleHandleW", err)
	}
	className, err := syscall.UTF16PtrFromString(windowClassName)
	if err != nil {
		return err
	}
	cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
	wc := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		Style:         csHRedraw | csVRedraw,
		LpfnWndProc:   syscall.NewCallback(windowProc),
		HInstance:     instance,
		HCursor:       cursor,
		HbrBackground: colorWindow + 1,
		LpszClassName: className,
	}
	atom, _, registerErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return callError("RegisterClassExW", registerErr)
	}

	title, _ := syscall.UTF16PtrFromString("WeDecent")
	useDefault := uintptr(uint32(0x80000000))
	hwnd, _, createErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		wsOverlappedWindow,
		useDefault,
		useDefault,
		900,
		650,
		0,
		0,
		instance,
		0,
	)
	if hwnd == 0 {
		if app.startErr != nil {
			return app.startErr
		}
		return callError("CreateWindowExW", createErr)
	}
	app.hwnd = hwnd
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
	app.refreshAsync()

	var message msg
	for {
		result, _, getErr := procGetMessageW.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(result) == -1 {
			return callError("GetMessageW", getErr)
		}
		if result == 0 {
			return nil
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&message)))
	}
}

func showFatal(err error) {
	if err == nil {
		return
	}
	title, _ := syscall.UTF16PtrFromString("WeDecent")
	message, convErr := syscall.UTF16PtrFromString(err.Error())
	if convErr != nil {
		message, _ = syscall.UTF16PtrFromString("WeDecent encountered an error.")
	}
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x10)
}

func windowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	app := activeApp
	if app == nil {
		result, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
		return result
	}

	switch message {
	case wmCreate:
		app.hwnd = hwnd
		if err := app.createControls(); err != nil {
			app.startErr = err
			return ^uintptr(0)
		}
		return 0
	case wmSize:
		app.layout(int(uint16(lParam)), int(uint16(lParam>>16)))
		return 0
	case wmExitSizeMove:
		app.resizeAsync()
		return 0
	case wmCommand:
		app.handleCommand(uint16(wParam), uint16(wParam>>16))
		return 0
	case wmAppEvent:
		app.handleEvent(wParam)
		return 0
	case wmClose:
		app.closeAsync()
		return 0
	case wmDestroy:
		app.stopReader()
		app.discardEvents()
		procPostQuitMessage.Call(0)
		return 0
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return result
}

func (a *winApp) createControls() error {
	var err error
	if a.status, err = createControl("STATIC", "Starting Local Core client…", wsChild|wsVisible, 0, 0, 10, 10, 500, 24, a.hwnd); err != nil {
		return err
	}
	if a.refresh, err = createControl("BUTTON", "Refresh", wsChild|wsVisible|wsTabStop, 0, idRefresh, 0, 0, 90, 28, a.hwnd); err != nil {
		return err
	}
	if a.devicesBox, err = createControl("LISTBOX", "", wsChild|wsVisible|wsBorder|wsVScroll|lbsNotify, 0, idDevices, 0, 0, 300, 300, a.hwnd); err != nil {
		return err
	}
	if a.connect, err = createControl("BUTTON", "Connect", wsChild|wsVisible|wsTabStop, 0, idConnect, 0, 0, 90, 28, a.hwnd); err != nil {
		return err
	}
	if a.disconnect, err = createControl("BUTTON", "Disconnect", wsChild|wsVisible|wsTabStop, 0, idDisconnect, 0, 0, 100, 28, a.hwnd); err != nil {
		return err
	}
	if a.output, err = createControl("EDIT", "", wsChild|wsVisible|wsBorder|wsVScroll|esMultiline|esAutoVScroll|esReadOnly|esWantReturn, 0, idOutput, 0, 0, 500, 400, a.hwnd); err != nil {
		return err
	}
	if a.input, err = createControl("EDIT", "", wsChild|wsVisible|wsBorder|wsTabStop|esAutoHScroll, 0, idInput, 0, 0, 400, 28, a.hwnd); err != nil {
		return err
	}
	procSendMessageW.Call(a.input, emSetLimitText, uintptr(maxTerminalInputChars), 0)
	if a.send, err = createControl("BUTTON", "Send", wsChild|wsVisible|wsTabStop, 0, idSend, 0, 0, 80, 28, a.hwnd); err != nil {
		return err
	}

	font, _, _ := procGetStockObject.Call(defaultGUIFont)
	for _, control := range []uintptr{a.status, a.refresh, a.devicesBox, a.connect, a.disconnect, a.output, a.input, a.send} {
		procSendMessageW.Call(control, wmSetFont, font, 1)
	}
	a.updateControls()
	return nil
}

func createControl(className, text string, style, exStyle, id uintptr, x, y, width, height int, parent uintptr) (uintptr, error) {
	classPtr, err := syscall.UTF16PtrFromString(className)
	if err != nil {
		return 0, err
	}
	textPtr, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return 0, err
	}
	instance, _, callErr := procGetModuleHandleW.Call(0)
	if instance == 0 {
		return 0, callError("GetModuleHandleW", callErr)
	}
	hwnd, _, createErr := procCreateWindowExW.Call(
		exStyle,
		uintptr(unsafe.Pointer(classPtr)),
		uintptr(unsafe.Pointer(textPtr)),
		style,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height),
		parent,
		id,
		instance,
		0,
	)
	if hwnd == 0 {
		return 0, callError("CreateWindowExW "+className, createErr)
	}
	return hwnd, nil
}

func (a *winApp) layout(width, height int) {
	if width < 650 {
		width = 650
	}
	if height < 400 {
		height = 400
	}
	a.clientWidth, a.clientHeight = width, height

	move(a.status, 10, 10, width-120, 24)
	move(a.refresh, width-100, 8, 90, 28)
	move(a.devicesBox, 10, 44, 300, height-94)
	move(a.connect, 10, height-40, 90, 28)
	move(a.disconnect, 110, height-40, 100, 28)
	move(a.output, 320, 44, width-330, height-94)
	move(a.input, 320, height-40, width-420, 28)
	move(a.send, width-90, height-40, 80, 28)
}

func move(hwnd uintptr, x, y, width, height int) {
	if hwnd != 0 {
		procMoveWindow.Call(hwnd, uintptr(x), uintptr(y), uintptr(width), uintptr(height), 1)
	}
}

func (a *winApp) handleCommand(id, notification uint16) {
	if a.closingApp {
		return
	}
	switch id {
	case idRefresh:
		if notification == bnClicked {
			a.refreshAsync()
		}
	case idConnect:
		if notification == bnClicked {
			a.connectAsync()
		}
	case idDisconnect:
		if notification == bnClicked {
			a.disconnectAsync()
		}
	case idSend:
		if notification == bnClicked {
			a.sendAsync()
		}
	case idDevices:
		if notification == lbnSelChange {
			a.updateControls()
		}
	}
}

func (a *winApp) refreshAsync() {
	if a.busyRefresh || a.closingApp {
		return
	}
	a.busyRefresh = true
	a.updateControls()
	a.setStatus("Refreshing Local Core…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		snapshot, err := a.controller.Refresh(ctx)
		event := uiEvent{kind: eventRefreshDone, snapshot: snapshot}
		if err != nil {
			event.message = publicError(err)
		}
		a.postEvent(event)
	}()
}

func (a *winApp) connectAsync() {
	if a.busyConnect || a.busyDisconnect || a.closingApp {
		return
	}
	index := a.selectedDeviceIndex()
	if index < 0 || index >= len(a.devices) {
		a.setStatus("Select a trusted device first.")
		return
	}
	device := a.devices[index]
	a.busyConnect = true
	a.updateControls()
	a.setStatus("Connecting to " + displayDevice(device) + "…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		connection, err := a.controller.Connect(ctx, device.ID)
		event := uiEvent{kind: eventConnectDone, connection: connection}
		if err != nil {
			event.message = publicError(err)
		}
		a.postEvent(event)
	}()
}

func (a *winApp) disconnectAsync() {
	if a.busyDisconnect || a.closingApp {
		return
	}
	if _, ok := a.controller.ActiveConnection(); !ok {
		return
	}
	a.stopReader()
	a.busyDisconnect = true
	a.updateControls()
	a.setStatus("Disconnecting…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		err := a.controller.Disconnect(ctx)
		event := uiEvent{kind: eventDisconnectDone}
		if err != nil {
			event.message = publicError(err)
		}
		a.postEvent(event)
	}()
}

func (a *winApp) sendAsync() {
	if a.busySend || a.closingApp {
		return
	}
	if _, ok := a.controller.ActiveConnection(); !ok {
		return
	}
	text, err := windowText(a.input)
	if err != nil {
		a.setStatus("Could not read terminal input.")
		return
	}
	if text == "" {
		return
	}
	data := []byte(text + "\r")
	if len(data) > v1.MaxTerminalChunkBytes {
		for i := range data {
			data[i] = 0
		}
		a.setStatus("Terminal input is limited to 32 KiB.")
		return
	}
	a.busySend = true
	a.updateControls()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		err := a.controller.WriteTerminal(ctx, data)
		for i := range data {
			data[i] = 0
		}
		event := uiEvent{kind: eventSendDone}
		if err != nil {
			event.message = publicError(err)
		}
		a.postEvent(event)
	}()
}

func (a *winApp) resizeAsync() {
	if a.closingApp {
		return
	}
	if _, ok := a.controller.ActiveConnection(); !ok {
		return
	}
	cols := clamp(a.clientWidth-340, 160, 3200) / 8
	rows := clamp(a.clientHeight-150, 80, 3200) / 16
	go func(cols, rows uint16) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := a.controller.ResizeTerminal(ctx, cols, rows)
		if err != nil && !errors.Is(err, guiapp.ErrNoSession) && !errors.Is(err, context.Canceled) {
			a.postEvent(uiEvent{kind: eventResizeDone, message: publicError(err)})
		}
	}(uint16(cols), uint16(rows))
}

func (a *winApp) startReader() {
	a.stopReader()
	if _, ok := a.controller.ActiveConnection(); !ok {
		return
	}
	a.sessionSeq++
	session := a.sessionSeq
	ctx, cancel := context.WithCancel(context.Background())
	a.readCancel = cancel
	go func() {
		for {
			result, err := a.controller.ReadTerminal(ctx, v1.MaxTerminalChunkBytes)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				a.postEvent(uiEvent{kind: eventTerminalError, session: session, message: publicError(err)})
				return
			}
			if len(result.Data) != 0 {
				ack := make(chan struct{})
				if !a.postEvent(uiEvent{
					kind:    eventTerminalData,
					session: session,
					data:    append([]byte(nil), result.Data...),
					ack:     ack,
				}) {
					return
				}
				select {
				case <-ack:
				case <-ctx.Done():
					return
				}
			}
			if result.Closed {
				a.postEvent(uiEvent{kind: eventTerminalClosed, session: session})
				return
			}
		}
	}()
}

func (a *winApp) stopReader() {
	if a.readCancel != nil {
		a.readCancel()
		a.readCancel = nil
	}
}

func (a *winApp) closeAsync() {
	if a.closingApp {
		return
	}
	if _, ok := a.controller.ActiveConnection(); !ok {
		procDestroyWindow.Call(a.hwnd)
		return
	}
	a.closingApp = true
	a.stopReader()
	procEnableWindow.Call(a.hwnd, 0)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = a.controller.Disconnect(ctx)
		a.postEvent(uiEvent{kind: eventExitReady})
	}()
}

func (a *winApp) handleEvent(token uintptr) {
	event, ok := a.takeEvent(token)
	if !ok {
		return
	}
	if event.ack != nil {
		defer close(event.ack)
	}

	switch event.kind {
	case eventRefreshDone:
		a.busyRefresh = false
		if event.message != "" {
			a.setStatus(event.message)
		} else {
			a.devices = append(a.devices[:0], event.snapshot.Devices...)
			a.populateDevices()
			a.setStatus(statusText(event.snapshot.Status))
		}
		a.updateControls()
	case eventConnectDone:
		a.busyConnect = false
		if event.message != "" {
			a.setStatus(event.message)
		} else {
			a.setStatus(fmt.Sprintf("Connected to %s via %s.", event.connection.DeviceID, event.connection.Path))
			a.appendOutput("\r\n--- connected ---\r\n")
			a.startReader()
			a.resizeAsync()
		}
		a.updateControls()
	case eventDisconnectDone:
		a.busyDisconnect = false
		if event.message != "" {
			a.setStatus("Disconnect failed: " + event.message)
			if _, ok := a.controller.ActiveConnection(); ok {
				a.startReader()
			}
		} else {
			a.setStatus("Disconnected.")
			a.appendOutput("\r\n--- disconnected ---\r\n")
		}
		a.updateControls()
	case eventTerminalData:
		if event.session == a.sessionSeq {
			a.appendTerminalData(event.data)
		}
	case eventTerminalClosed:
		if event.session == a.sessionSeq {
			a.stopReader()
			a.setStatus("Remote terminal closed.")
			a.appendOutput("\r\n--- remote terminal closed ---\r\n")
			a.updateControls()
		}
	case eventTerminalError:
		if event.session == a.sessionSeq {
			a.stopReader()
			a.setStatus("Terminal read stopped: " + event.message)
			a.updateControls()
		}
	case eventSendDone:
		a.busySend = false
		if event.message != "" {
			a.setStatus("Send failed: " + event.message)
		} else {
			setWindowText(a.input, "")
		}
		a.updateControls()
	case eventResizeDone:
		if event.message != "" {
			a.setStatus("Terminal resize failed: " + event.message)
		}
	case eventExitReady:
		procDestroyWindow.Call(a.hwnd)
	}
}

func (a *winApp) postEvent(event uiEvent) bool {
	a.eventMu.Lock()
	a.nextEvent++
	if a.nextEvent == 0 {
		a.nextEvent++
	}
	token := a.nextEvent
	a.events[token] = event
	a.eventMu.Unlock()

	result, _, _ := procPostMessageW.Call(a.hwnd, wmAppEvent, token, 0)
	if result != 0 {
		return true
	}

	a.eventMu.Lock()
	failed, ok := a.events[token]
	if ok {
		delete(a.events, token)
	}
	a.eventMu.Unlock()
	if ok && failed.ack != nil {
		close(failed.ack)
	}
	return false
}

func (a *winApp) takeEvent(token uintptr) (uiEvent, bool) {
	a.eventMu.Lock()
	defer a.eventMu.Unlock()
	event, ok := a.events[token]
	if ok {
		delete(a.events, token)
	}
	return event, ok
}

func (a *winApp) discardEvents() {
	a.eventMu.Lock()
	events := a.events
	a.events = make(map[uintptr]uiEvent)
	a.eventMu.Unlock()
	for _, event := range events {
		if event.ack != nil {
			close(event.ack)
		}
	}
}

func (a *winApp) populateDevices() {
	procSendMessageW.Call(a.devicesBox, lbResetContent, 0, 0)
	for _, device := range a.devices {
		label, err := syscall.UTF16PtrFromString(displayDevice(device))
		if err != nil {
			continue
		}
		procSendMessageW.Call(a.devicesBox, lbAddString, 0, uintptr(unsafe.Pointer(label)))
	}
}

func (a *winApp) selectedDeviceIndex() int {
	result, _, _ := procSendMessageW.Call(a.devicesBox, lbGetCurSel, 0, 0)
	index := int(int32(result))
	if index < 0 || index >= len(a.devices) {
		return -1
	}
	return index
}

func (a *winApp) updateControls() {
	_, active := a.controller.ActiveConnection()
	selection := a.selectedDeviceIndex() >= 0
	enable(a.refresh, !a.busyRefresh && !a.closingApp)
	enable(a.devicesBox, !a.busyConnect && !a.busyDisconnect && !a.closingApp)
	enable(a.connect, selection && !active && !a.busyConnect && !a.busyDisconnect && !a.closingApp)
	enable(a.disconnect, active && !a.busyDisconnect && !a.closingApp)
	enable(a.input, active && !a.busyDisconnect && !a.closingApp)
	enable(a.send, active && !a.busySend && !a.busyDisconnect && !a.closingApp)
}

func enable(hwnd uintptr, enabled bool) {
	value := uintptr(0)
	if enabled {
		value = 1
	}
	procEnableWindow.Call(hwnd, value)
}

func (a *winApp) setStatus(text string) {
	setWindowText(a.status, text)
}

func setWindowText(hwnd uintptr, text string) {
	text = strings.ReplaceAll(text, "\x00", "�")
	ptr, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	procSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(ptr)))
}

func windowText(hwnd uintptr) (string, error) {
	length, _, _ := procGetWindowTextLen.Call(hwnd)
	buffer := make([]uint16, int(length)+1)
	result, _, callErr := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if result == 0 && length != 0 {
		return "", callError("GetWindowTextW", callErr)
	}
	return syscall.UTF16ToString(buffer), nil
}

func (a *winApp) appendTerminalData(data []byte) {
	text := strings.ToValidUTF8(string(data), "�")
	text = strings.ReplaceAll(text, "\x00", "␀")
	text = strings.ReplaceAll(text, "\x1b", "␛")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	a.appendOutput(text)
}

func (a *winApp) appendOutput(text string) {
	if text == "" {
		return
	}
	length, _, _ := procGetWindowTextLen.Call(a.output)
	if int(length)+len(text) > maxTerminalDisplayChars {
		setWindowText(a.output, "--- earlier terminal output truncated ---\r\n")
		length, _, _ = procGetWindowTextLen.Call(a.output)
	}
	procSendMessageW.Call(a.output, emSetSel, length, length)
	ptr, err := syscall.UTF16PtrFromString(strings.ReplaceAll(text, "\x00", "␀"))
	if err != nil {
		return
	}
	procSendMessageW.Call(a.output, emReplaceSel, 0, uintptr(unsafe.Pointer(ptr)))
}

func displayDevice(device v1.Device) string {
	name := strings.TrimSpace(device.Name)
	if name == "" {
		return device.ID
	}
	return name + " (" + device.ID + ")"
}

func statusText(status v1.Status) string {
	device := strings.TrimSpace(status.DeviceName)
	if device == "" {
		device = status.DeviceID
	} else {
		device += " (" + status.DeviceID + ")"
	}
	if status.SignedIn {
		identity := strings.TrimSpace(status.Email)
		if identity == "" {
			identity = status.UserID
		}
		return "Local device: " + device + " • Signed in: " + identity
	}
	return "Local device: " + device + " • Signed out"
}

func publicError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Local Core request timed out."
	}
	if errors.Is(err, context.Canceled) {
		return "Local Core request was canceled."
	}
	if errors.Is(err, guiapp.ErrSessionActive) {
		return "A terminal session is already active."
	}
	if errors.Is(err, guiapp.ErrNoSession) {
		return "There is no active terminal session."
	}
	if errors.Is(err, guiapp.ErrInvalidDeviceID) {
		return "The selected device is invalid."
	}
	if errors.Is(err, guiapp.ErrTerminalInputTooLarge) {
		return "Terminal input is limited to 32 KiB."
	}
	var remote *coreclient.RemoteError
	if errors.As(err, &remote) {
		return remote.Message
	}
	return "Local Core is unavailable. Start wd-core for this user and try again."
}

func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func callError(operation string, err error) error {
	if err == nil || err == syscall.Errno(0) {
		return errors.New(operation + " failed")
	}
	return fmt.Errorf("%s: %w", operation, err)
}
