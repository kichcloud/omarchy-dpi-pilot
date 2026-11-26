import QtQuick
import QtQuick.Layouts
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "DpiModel.js" as DpiModel

pragma ComponentBehavior: Bound

/*
 * DPI Pilot drawer for the merged Network + DPI Pilot widget. Everything
 * network-related lives in the host Panel; this item owns only zapret2/WARP
 * state, the action processes and its compact disclosure UI.
 */
Item {
  id: root

  property var bar: null
  property bool expanded: false
  // The host panel is open; poll only while it can actually be seen.
  property bool active: false
  signal toggleRequested()
  signal drawerReady(var drawer)
  signal drawerGone()

  Component.onDestruction: root.drawerGone()

  property var st: null
  // "No status reply yet" is not a broken service; only a failed status
  // process means "нет связи". The panel holds keybinds until drawerReady,
  // so actions never see a null status here.
  property bool statusReachable: true
  property bool drawerPublished: false
  property var lastCheckAll: null
  property string actionName: ""
  // A click made while setup/repair is still running must not be lost.
  property var queuedActions: []
  property string actionError: ""
  // Errors from command results stay until the next action; status polls
  // must not erase a cancelled pkexec dialog.
  property bool actionErrorSticky: false
  property string flashText: ""
  property bool advanced: false
  property bool removeArmed: false

  readonly property string bin: {
    var path = String(Qt.resolvedUrl("kich-dpi") || "")
    if (path.indexOf("file://") === 0) path = path.substring(7)
    return decodeURIComponent(path)
  }
  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color accent: Commons.Color.accent
  readonly property color dim: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.58)
  readonly property color panelFill: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.06)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property bool installed: st !== null && st.installed === true
  readonly property bool running: st !== null && st.running === true
  readonly property bool failed: st !== null && st.failed === true
  readonly property bool generating: st !== null && st.generating === true
  readonly property bool busy: actionName !== ""
  readonly property bool warpRunning: warp.running === true
  readonly property var progress: st !== null && st.progress ? st.progress : ({})
  readonly property var check: st !== null && st.check ? st.check : ({})
  readonly property var results: check && check.results ? check.results : []
  readonly property var strategies: st && st.strategies ? st.strategies : []
  readonly property var warp: st !== null && st.warp ? st.warp : ({})
  readonly property var warpCheck: warp.check ? warp.check : ({})
  readonly property string warpCheckText: DpiModel.warpCheckText(warpCheck, Date.now())
  readonly property string warpText: DpiModel.warpText(warp, warpCheckText)
  readonly property string stateText: DpiModel.stateText(statusReachable, installed, failed, running)
  readonly property string errorText: actionError !== ""
    ? actionError : (installed && st && st.error ? st.error : "")
  readonly property bool dpiUnhealthy: DpiModel.dpiUnhealthy(st, Date.now())
  readonly property bool warpUnhealthy: DpiModel.warpUnhealthy(st, Date.now())
  readonly property bool unhealthy: DpiModel.hasProblem(st, Date.now())
  readonly property string diagnosticLine: DpiModel.diagnosticLine(st, lastCheckAll)
  readonly property bool diagnosticProblem: DpiModel.diagnosticProblem(lastCheckAll)

  width: parent ? parent.width : 0
  implicitHeight: column.implicitHeight

  component PilotText: Text {
    property int fontSize: Style.font.caption
    textFormat: Text.PlainText
    font.family: root.fontFamily
    font.pixelSize: fontSize
    color: root.foreground
    wrapMode: Text.Wrap
    elide: Text.ElideNone
  }

  // Stock kit buttons: theme-owned square corners, hover/press fills, focus
  // ring, press scale and tooltips instead of hand-rolled Qt button chrome.
  component PilotButton: Button {
    id: control
    property color tint: root.foreground
    property bool danger: false
    property bool blocked: false
    implicitHeight: Style.space(34)
    enabled: !blocked && !root.busy
    opacity: enabled ? 1 : 0.5
    foreground: control.danger ? root.urgent : control.tint
    accent: control.danger ? root.urgent : root.accent
    fontSize: Style.font.bodySmall
    fontFamily: root.fontFamily
    // Same resting outline as the DNS provider pills in the stock section.
    horizontalPadding: Style.spacing.controlPaddingX
    verticalPadding: Style.spacing.controlPaddingY + Style.space(2)
    bordered: true
    Behavior on opacity { NumberAnimation { duration: Style.duration(120) } }
  }

  component IconButton: PanelActionButton {
    id: control
    property string glyph: ""
    property string hint: ""
    property color tint: root.foreground
    iconText: control.glyph
    tooltipText: control.hint
    foreground: control.tint
    hoverColor: control.tint
    enabled: !root.busy
  }

  // The disclosure header is a stock-style surface: square corners, shared
  // hover/pressed tokens, a press that gives a little, and the DPI shield.
  component HeaderButton: BorderSurface {
    id: control
    property string glyph: ""
    property string title: ""
    property string detail: ""
    property bool attention: false
    property bool opened: false
    signal clicked()

    implicitHeight: Math.max(brand.implicitHeight, labels.implicitHeight)
      + Style.space(6)
    radius: Style.cornerRadius

    readonly property bool hot: mouse.containsMouse
    readonly property var hoverBorder: Border.controlSpec(
      "hover-cursor", root.foreground, root.accent)

    color: mouse.pressed ? Style.pressedFillFor(root.foreground, root.accent)
      : hot ? Style.hoverFillFor(root.foreground, root.accent)
      : "transparent"
    borderSpec: hot ? hoverBorder : Border.none()
    Behavior on color { ColorAnimation { duration: Style.duration(120) } }

    scale: mouse.pressed ? 0.97 : 1
    Behavior on scale {
      NumberAnimation {
        duration: Style.duration(160)
        easing.type: Easing.Bezier
        easing.bezierCurve: Style.easeOut
      }
    }

    Row {
      // No margin: the shield starts at the same x as the stock network icon
      // in the hero above, so the two form one left-aligned icon column.
      // The wider gap matches the stock row's icon-to-label distance too.
      anchors.fill: parent
      spacing: Style.space(14)

      PilotText {
        id: brand
        anchors.verticalCenter: parent.verticalCenter
        text: control.glyph
        // Match the display-sized network icon in the stock hero above.
        fontSize: Style.font.display
        color: control.attention ? root.urgent : root.foreground
        wrapMode: Text.NoWrap
      }

      Column {
        id: labels
        width: parent.width - brand.implicitWidth - chevron.implicitWidth
          - parent.spacing * 2
        anchors.verticalCenter: parent.verticalCenter
        spacing: 1

        PilotText {
          width: parent.width
          text: control.title
          fontSize: Style.font.subtitle
          font.bold: true
          color: control.attention ? root.urgent : root.foreground
          wrapMode: Text.NoWrap
        }
        PilotText {
          width: parent.width
          text: control.detail
          color: control.attention ? root.urgent : root.dim
          elide: Text.ElideRight
          wrapMode: Text.NoWrap
        }
      }

      PilotText {
        id: chevron
        anchors.verticalCenter: parent.verticalCenter
        text: control.opened ? "▴" : "▾"
        fontSize: Style.font.body
        color: control.hot ? root.accent : root.dim
        wrapMode: Text.NoWrap
      }
    }

    MouseArea {
      id: mouse
      anchors.fill: parent
      // Undo the press scale so a press near the edge still counts as a click.
      scale: 1 / control.scale
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: control.clicked()
    }
  }

  // Label and status on the left, a real ToggleSwitch on the right.
  component SwitchCard: BorderSurface {
    id: card
    property string title
    property string detail
    property bool isOn
    property bool attention: false
    property bool busy: false
    property color accentColor: root.foreground
    signal toggled()

    width: parent.width
    implicitHeight: cardRow.implicitHeight + Style.space(20)
    color: Style.normalFillFor(root.foreground, root.accent)
    borderSpec: Border.flat(
      Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.14), 1)
    radius: Style.cornerRadius

    RowLayout {
      id: cardRow
      anchors.fill: parent
      anchors.leftMargin: Style.space(12)
      anchors.rightMargin: Style.space(12)
      spacing: Style.space(10)

      ColumnLayout {
        Layout.fillWidth: true
        spacing: 2
        PilotText {
          text: card.title
          fontSize: Style.font.subtitle
          font.bold: true
          color: root.foreground
        }
        PilotText {
          Layout.fillWidth: true
          text: card.detail
          color: card.attention ? root.urgent : root.dim
          wrapMode: Text.WordWrap
        }
      }
      ToggleSwitch {
        checked: card.isOn
        busy: card.busy
        foreground: root.foreground
        accent: card.accentColor
        Layout.alignment: Qt.AlignVCenter
        onToggled: card.toggled()
      }
    }
  }

  function refresh() {
    if (!statusProc.running) statusProc.running = true
  }

  function flash(text) {
    flashText = text
    flashTimer.restart()
  }

  function applyStatus(code, text, err) {
    if (code !== 0) {
      statusReachable = false
      actionErrorSticky = false
      if (actionError === "") actionError = DpiModel.shortError(err) || "Менеджер не запустился"
      return
    }
    var parsed = DpiModel.parseJsonOutput(text)
    if (!parsed || parsed.ok !== true) {
      statusReachable = false
      actionErrorSticky = false
      if (actionError === "") actionError = parsed && parsed.error ? parsed.error : "Пустой ответ менеджера"
      return
    }
    st = parsed
    statusReachable = true
    if (!actionErrorSticky) actionError = ""
    // Only a successful status reply proves the drawer is ready for keybinds.
    if (!drawerPublished) {
      drawerPublished = true
      root.drawerReady(root)
    }
  }

  function ipc(name) {
    DpiModel.invoke(root, name)
  }

  function startAction(name, command, label) {
    if (actionProc.running) {
      queuedActions.push({name: name, command: command, label: label})
      return
    }
    actionError = ""
    actionErrorSticky = false
    actionName = name
    actionProc.command = command
    actionProc.running = true
    if (label !== "") flash(label)
  }

  function drainActions() {
    if (actionProc.running || queuedActions.length === 0) return
    var next = queuedActions.shift()
    startAction(next.name, next.command, next.label)
  }

  function finishAction(code, text, err) {
    var name = actionName
    actionName = ""
    var parsed = DpiModel.parseJsonOutput(text)

    var outcome = DpiModel.actionResult(name, parsed, code, err)
    if (outcome.checkAll) lastCheckAll = outcome.checkAll
    if (outcome.error) {
      actionError = outcome.error
      actionErrorSticky = true
    }
    if (outcome.advanced) advanced = false
    if (outcome.flash) flash(outcome.flash)

    if (outcome.reuseStatus) {
      applyStatus(0, text, "")
      drainActions()
      return
    }
    if (outcome.reuseWarp) {
      if (st) {
        const next = Object.assign({}, st)
        next.warp = outcome.reuseWarp
        st = next
      }
      if (outcome.followUpWarpCheck)
        startAction("warp-check", [bin, "warp-check"], "Проверка WARP…")
      drainActions()
      return
    }
    if (outcome.refresh) refresh()
    drainActions()
  }

  function installEngine() {
    startAction("install", ["pkexec", bin, "setup"], "Установка движка…")
  }

  function toggleBypass() {
    if (!installed) { installEngine(); return }
    if (generating) return
    startAction("toggle", [bin, "toggle"], running ? "Выключение…" : "Включение…")
  }

  function runDiagnostics() {
    if (generating) return
    startAction("check-all", [bin, "check-all"], "Проверка…")
  }

  function runRepair() {
    if (!installed || generating) return
    startAction("repair", ["pkexec", bin, "repair"], "Восстановление…")
  }

  function runGenerate() {
    if (!installed) return
    startAction("generate", [bin, "generate"], "Подбор стратегий…")
  }

  function updateEngine() {
    startAction("update", ["pkexec", bin, "setup"], "Обновление движка…")
  }

  function toggleWarp() {
    if (!installed) { installEngine(); return }
    if (generating) return
    if (!warp.available) {
      startAction("install", ["pkexec", bin, "setup"], "Установка mihomo…")
      return
    }
    startAction("warp", [bin, "warp-toggle"],
                warpRunning ? "Отключение WARP…" : "Подключение WARP…")
  }

  function registerWarp() {
    startAction("warp-register", [bin, "warp-register"], "Регистрация WARP…")
  }

  function checkWarp() {
    startAction("warp-check", [bin, "warp-check"], "Проверка WARP…")
  }

  function useStrategy(id) {
    startAction("use", [bin, "use", id], "Применение стратегии…")
  }

  function runDoctor() {
    startAction("doctor", [bin, "doctor"], "Диагностика…")
  }

  function removeEngine() {
    if (!removeArmed) {
      removeArmed = true
      armTimer.restart()
      flash("Нажмите ещё раз для удаления")
      return
    }
    removeArmed = false
    startAction("remove", ["pkexec", bin, "remove", "--purge"], "Удаление…")
  }

  Column {
    id: column
    width: parent.width
    spacing: Style.space(10)

    // The header stays visible; everything else collapses behind it.
    Row {
      id: headerRow
      width: parent.width
      spacing: Style.space(6)

      HeaderButton {
        id: headerButton
        width: parent.width - repairButton.implicitWidth
          - refreshButton.implicitWidth - parent.spacing * 2
        anchors.verticalCenter: parent.verticalCenter
        glyph: "󰒘"
        title: "DPI Pilot"
        detail: DpiModel.joinDetail([root.stateText, root.diagnosticLine])
        attention: root.unhealthy
        opened: root.expanded
        onClicked: root.toggleRequested()
      }

      IconButton {
        id: repairButton
        anchors.verticalCenter: parent.verticalCenter
        glyph: "󰋑"
        hint: "Восстановить"
        tint: root.dpiUnhealthy || root.warpUnhealthy
          ? root.urgent : root.foreground
        onClicked: root.runRepair()
      }
      IconButton {
        id: refreshButton
        anchors.verticalCenter: parent.verticalCenter
        glyph: "󰑐"
        hint: "Обновить"
        onClicked: root.refresh()
      }
    }

    Column {
      id: details
      width: parent.width
      visible: root.expanded
      spacing: Style.space(10)

      Column {
        width: parent.width
        spacing: Style.space(8)
        visible: !root.installed
        PilotText {
          width: parent.width
          text: "Движок zapret2 ещё не установлен. Установка скачает официальный релиз bol-van/zapret2 и один раз попросит пароль."
          color: root.dim
        }
        PilotButton {
          width: parent.width
          text: "Установить"
          onClicked: root.installEngine()
        }
      }

      SwitchCard {
        visible: root.installed
        title: "Обход DPI"
        detail: root.failed ? "Служба не запустилась — смотрите журнал"
          : root.running ? "Трафик идёт через nfqws2"
          : "Готов включить подобранную стратегию"
        isOn: root.running
        attention: root.dpiUnhealthy
        busy: root.busy || root.generating
        accentColor: root.dpiUnhealthy ? root.urgent : root.foreground
        onToggled: root.toggleBypass()
      }

      SwitchCard {
        visible: root.installed
        title: "WARP"
        detail: root.warpText
        isOn: root.warpRunning
        attention: root.warpUnhealthy
        busy: root.busy || root.generating
        accentColor: root.warpUnhealthy ? root.urgent : root.foreground
        onToggled: root.toggleWarp()
      }

      Column {
        width: parent.width
        spacing: Style.space(6)
        // Stale probe rows are not shown for a service the user switched off.
        visible: root.installed && root.running

        PilotText {
          text: "ДОСТУПНОСТЬ"
          fontSize: Style.font.caption
          color: root.dim
        }
        Row {
          width: parent.width
          spacing: Style.space(12)
          Repeater {
            model: [
              { key: "youtube", label: "YouTube" },
              { key: "discord", label: "Discord" },
              { key: "google", label: "Google" }
            ]
            delegate: Row {
              required property var modelData
              spacing: Style.space(6)
              readonly property var result: DpiModel.findResult(root.results, modelData.key)
              Rectangle {
                width: Style.space(7)
                height: width
                radius: width / 2
                anchors.verticalCenter: parent.verticalCenter
                color: parent.result === null ? "transparent"
                  : parent.result.ok ? root.accent : root.urgent
                border.color: parent.result === null ? root.dim : "transparent"
                border.width: parent.result === null ? 1 : 0
              }
              PilotText {
                text: parent.modelData.label
                color: parent.result === null ? root.dim : root.foreground
                anchors.verticalCenter: parent.verticalCenter
              }
            }
          }
        }
        PilotText {
          text: DpiModel.whenText(root.check, Date.now())
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.35)
        }
      }

      Row {
        width: parent.width
        spacing: Style.space(8)
        PilotButton {
          width: (parent.width - parent.spacing) / 2
          text: root.generating ? "Подбор идёт…" : "Подобрать"
          blocked: root.generating
          onClicked: root.runGenerate()
        }
        PilotButton {
          width: (parent.width - parent.spacing) / 2
          text: root.actionName === "check-all" ? "Проверка…" : "Проверить"
          onClicked: root.runDiagnostics()
        }
      }

      Column {
        width: parent.width
        spacing: Style.space(6)
        visible: root.generating
        PilotText {
          text: "Подбор стратегий"
          color: root.foreground
          font.bold: true
        }
        Rectangle {
          width: parent.width
          height: Style.space(4)
          radius: height / 2
          color: root.panelFill
          Rectangle {
            width: parent.width * Math.min(1, (root.progress.done || 0)
              / Math.max(1, root.progress.total || 1))
            height: parent.height
            radius: parent.radius
            color: root.accent
          }
        }
        PilotText {
          text: DpiModel.progressText(root.progress)
          color: root.dim
          elide: Text.ElideRight
          wrapMode: Text.NoWrap
        }
      }

      PilotText {
        width: parent.width
        visible: root.errorText !== ""
        text: root.errorText
        color: root.urgent
      }
      PilotText {
        width: parent.width
        visible: root.flashText !== ""
        text: root.flashText
        color: root.accent
      }

      Column {
        width: parent.width
        spacing: Style.space(6)
        visible: root.installed

        Rectangle {
          width: parent.width
          height: 1
          color: root.panelFill
        }
        PilotButton {
          width: parent.width
          text: root.advanced ? "Свернуть" : "Дополнительно"
          onClicked: root.advanced = !root.advanced
        }

        Column {
          width: parent.width
          spacing: Style.space(6)
          visible: root.advanced

          // The strategy list lives behind "Дополнительно" with the rest of
          // the service details.
          Column {
            width: parent.width
            spacing: Style.space(3)
            visible: root.strategies.length > 0
            PilotText { text: "Стратегии"; color: root.dim }
            Repeater {
              model: root.strategies
              delegate: PilotButton {
                required property var modelData
                width: parent.width
                text: modelData.name + " · " + modelData.passed + "/" + modelData.total
                onClicked: root.useStrategy(modelData.id)
              }
            }
          }

          PilotButton {
            width: parent.width
            text: "Обновить движок"
            onClicked: root.updateEngine()
          }
          PilotButton {
            width: parent.width
            text: "Перерегистрировать WARP"
            onClicked: root.registerWarp()
          }
          PilotButton {
            width: parent.width
            text: root.removeArmed ? "Точно удалить всё?" : "Удалить системную часть"
            danger: true
            onClicked: root.removeEngine()
          }
        }
      }
    }
  }

  Process {
    id: statusProc
    command: [root.bin, "status"]
    stdout: StdioCollector { id: statusOut }
    stderr: StdioCollector { id: statusErr }
    onExited: function(code) {
      root.applyStatus(code, String(statusOut.text || ""), String(statusErr.text || ""))
    }
  }

  Process {
    id: actionProc
    stdout: StdioCollector { id: actionOut }
    stderr: StdioCollector { id: actionErr }
    onExited: function(code) {
      root.finishAction(code, String(actionOut.text || ""), String(actionErr.text || ""))
    }
  }

  Timer {
    interval: root.generating ? 1200 : 2500
    running: root.active
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Timer {
    id: flashTimer
    interval: 3500
    onTriggered: root.flashText = ""
  }

  Timer {
    id: armTimer
    interval: 4000
    onTriggered: root.removeArmed = false
  }
}
