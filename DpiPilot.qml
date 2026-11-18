import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui

/*
 * DPI Pilot: one bar button and one small popup.
 *
 * There are no tabs, lists or preset screens. The panel shows whether the
 * bypass is on, which generated strategy is active, a three-site check, and
 * one button that rebuilds and measures strategies. Everything else (engine
 * update, removal) lives behind "Дополнительно".
 */
Panel {
  id: root
  moduleName: "kich.dpi-pilot"
  ipcTarget: "kich.dpi-pilot"
  manageIpc: false

  readonly property string bin: {
    var path = String(Qt.resolvedUrl("bin/kich-dpi") || "")
    if (path.indexOf("file://") === 0) path = path.substring(7)
    return decodeURIComponent(path)
  }

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color dim: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.58)
  readonly property color faint: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.35)
  readonly property color accent: Commons.Color.accent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // ---------------------------------------------------------------- state
  property var st: null
  property bool reachable: false
  property string actionName: ""
  property string actionLabel: ""
  property string actionError: ""
  property string flashText: ""
  property bool advanced: false
  property bool armRemove: false

  readonly property var state: st
  readonly property bool installed: st !== null && st.installed === true
  readonly property bool running: st !== null && st.running === true
  readonly property bool failed: st !== null && st.failed === true
  readonly property bool generating: st !== null && st.generating === true
  readonly property var progress: st !== null && st.progress ? st.progress : ({})
  readonly property var check: st !== null && st.check ? st.check : ({})
  readonly property var results: check && check.results ? check.results : []
  readonly property var strategies: st !== null && st.strategies ? st.strategies : []
  readonly property string strategyName: st !== null && st.active_name ? st.active_name : ""
  readonly property string activeId: st !== null && st.active_id ? String(st.active_id) : ""
  readonly property string engine: st !== null && st.engine ? st.engine : ""
  readonly property bool conflict: st !== null && st.conflict === true
  readonly property var warp: st !== null && st.warp ? st.warp : ({})
  readonly property bool warpAvailable: warp.available === true
  readonly property bool warpRunning: warp.running === true
  readonly property bool warpRegistered: warp.registered === true
  readonly property string warpConflict: warp.conflict ? String(warp.conflict) : ""
  readonly property string warpAccount: warp.account ? String(warp.account) : ""
  readonly property var warpCheck: warp.check ? warp.check : ({})
  function compactAddress(value) {
    var text = String(value || "")
    // WARP now prefers IPv6, and a full address is too wide for the popup.
    if (text.indexOf(":") < 0 || text.length <= 24) return text
    var parts = text.split(":")
    return parts.slice(0, 3).join(":") + "…" + parts.slice(-2).join(":")
  }
  readonly property string warpCheckText: {
    if (!warpCheck || !warpCheck.time) return ""
    if (Date.now() / 1000 - warpCheck.time > 900) return ""
    return warpCheck.ok && warpCheck.ip ? compactAddress(warpCheck.ip) : ""
  }
  readonly property string warpText: {
    if (!warpAvailable) return "mihomo не установлен — нажмите, чтобы доустановить"
    if (warpConflict !== "") return "Недоступен: " + warpConflict
    if (warpRunning) {
      if (warpCheckText !== "") {
        var route = warpCheck.tun === false ? " · маршрут не в туннеле" : ""
        return "Выход " + warpCheckText + (warpCheck.colo ? " · " + warpCheck.colo : "") + route
      }
      return "Туннель включён"
    }
    if (warp.failed === true) return "Служба не запустилась — смотрите журнал"
    if (warpRegistered) return "Готов включить туннель"
    return "Аккаунт Cloudflare создастся при включении"
  }
  readonly property bool busy: actionProc.running
  readonly property string errorText: actionError !== "" ? actionError
    : (st !== null && st.installed === true && st.error ? st.error : "")

  readonly property string stateText: !reachable ? "нет связи"
    : !installed ? "не установлен"
    : failed ? "ошибка"
    : running ? "включён"
    : "выключен"

  readonly property string tooltip: {
    if (!reachable) return "DPI Pilot · менеджер не отвечает"
    if (!installed) return "DPI Pilot · движок не установлен"
    var text = "DPI Pilot · " + stateText
    if (strategyName !== "") text += " · " + strategyName
    if (check && check.passed !== undefined) text += " · " + check.passed + "/" + (check.total || 3)
    if (warpRunning) text += " · WARP"
    return text
  }

  implicitWidth: barButton.implicitWidth
  implicitHeight: barButton.implicitHeight

  function shortError(text) {
    var value = String(text || "").split("\n")[0]
    return value.length > 120 ? value.substring(0, 117) + "…" : value
  }

  function flash(text) {
    flashText = text
    flashTimer.restart()
  }

  function findResult(key) {
    for (var i = 0; i < results.length; i++) {
      if (results[i] && results[i].key === key) return results[i]
    }
    return null
  }

  function whenText() {
    if (!check || !check.time) return "ещё не проверялось"
    var minutes = Math.floor((Date.now() / 1000 - check.time) / 60)
    if (minutes < 1) return "только что"
    if (minutes < 60) return minutes + " мин назад"
    return Math.floor(minutes / 60) + " ч назад"
  }

  function applyStatus(code, text, err) {
    if (code !== 0) {
      reachable = false
      if (actionError === "") actionError = shortError(err) || "Менеджер не запустился"
      return
    }
    var parsed = null
    try { parsed = JSON.parse(String(text || "")) } catch (e) {}
    if (!parsed || parsed.ok !== true) {
      reachable = false
      if (actionError === "") actionError = parsed && parsed.error ? parsed.error : "Пустой ответ менеджера"
      return
    }
    st = parsed
    reachable = true
  }

  function refresh() {
    if (statusProc.running) return
    statusProc.running = true
  }

  function startAction(name, command, label) {
    if (actionProc.running) return
    actionError = ""
    actionName = name
    actionLabel = label
    actionProc.command = command
    actionProc.running = true
  }

  function finishAction(code, text, err) {
    var name = actionName
    actionName = ""
    actionLabel = ""
    var parsed = null
    try { parsed = JSON.parse(String(text || "")) } catch (e) {}

    if (code === 126 || code === 127) {
      actionError = code === 126 ? "Отменено" : "Не найден pkexec"
    } else if (parsed && parsed.ok === false) {
      actionError = parsed.error || "Не удалось выполнить"
    } else if (code !== 0) {
      actionError = shortError(err) || ("Код " + code)
    } else if (name === "generate") {
      if (parsed && parsed.error) actionError = parsed.error
      else if (parsed && parsed.best) {
        flash("Лучшая: " + parsed.best.name + " · " + parsed.best.passed + "/" + parsed.best.total)
      } else flash("Подбор завершён")
    } else if (name === "check") {
      if (parsed && parsed.check) flash("Проверено: " + parsed.check.passed + "/" + parsed.check.total)
      else flash("Проверка завершена")
    } else if (name === "install" || name === "update") {
      flash(name === "install" ? "Движок установлен" : "Движок обновлён")
      if (parsed && parsed.warp === false && parsed.warp_note)
        actionError = "mihomo: " + parsed.warp_note
    } else if (name === "warp") {
      if (parsed && parsed.warp && parsed.warp.running === true) {
        flash("WARP подключён")
        startAction("warp-check", [bin, "warp-check"], "Проверка WARP…")
      } else {
        flash("WARP отключён")
      }
    } else if (name === "warp-check") {
      if (parsed && parsed.check && parsed.check.ok)
        flash("WARP работает" + (parsed.check.ip ? " · " + root.compactAddress(parsed.check.ip) : ""))
      else
        actionError = parsed && parsed.check && parsed.check.error
          ? parsed.check.error : "WARP не подтвердился"
    } else if (name === "remove") {
      advanced = false
      flash("Системная часть удалена")
    } else if (name === "use") {
      flash("Стратегия применена")
    }
    refresh()
  }

  function toggleBypass() {
    if (!installed) { installEngine(); return }
    if (busy || generating) return
    startAction("toggle", [bin, "toggle"], running ? "Выключение…" : "Включение…")
  }

  function runCheck() {
    if (!installed || busy || generating) return
    startAction("check", [bin, "check"], "Проверка сайтов…")
  }

  function runGenerate() {
    if (!installed || busy) return
    startAction("generate", [bin, "generate"], "Подбор стратегий…")
  }

  function installEngine() {
    if (busy) return
    startAction("install", ["pkexec", bin, "setup"], "Установка движка…")
  }

  function toggleWarp() {
    if (!installed) { installEngine(); return }
    if (busy || generating) return
    if (warpConflict !== "") {
      flash("Сначала выключите omarchy-usque")
      return
    }
    if (!warpAvailable) {
      startAction("install", ["pkexec", bin, "setup"], "Установка mihomo…")
      return
    }
    startAction("warp", [bin, "warp-toggle"], warpRunning ? "Отключение WARP…" : "Подключение WARP…")
  }

  function updateEngine() {
    if (busy) return
    startAction("update", ["pkexec", bin, "setup"], "Обновление движка…")
  }

  function removeEngine() {
    if (busy) return
    if (!armRemove) {
      armRemove = true
      armTimer.restart()
      return
    }
    armRemove = false
    startAction("remove", ["pkexec", bin, "remove"], "Удаление…")
  }

  function useStrategy(id) {
    if (!installed || id === "" || busy) return
    if (id === (st && st.active_id ? st.active_id : "")) return
    startAction("use", [bin, "use", id], "Применение…")
  }

  onOpenedChanged: if (opened) refresh()
  Component.onCompleted: refresh()

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
    interval: root.opened ? (root.generating ? 900 : 2500) : 8000
    running: true
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
    onTriggered: root.armRemove = false
  }

  IpcHandler {
    target: root.ipcTarget

    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.open() }
    function service(): void { root.toggleBypass() }
    function warp(): void { root.toggleWarp() }
    function check(): void { root.runCheck() }
    function generate(): void { root.runGenerate() }
    function refresh(): void { root.refresh() }
  }

  // ----------------------------------------------------------- primitives
  // Every label shares one family and two sizes, and every button shares the
  // same padding and disabled look: keeping that in components keeps the popup
  // itself about layout instead of styling.
  component DpiText: Text {
    property bool wrap: false
    property int size: Style.font.caption
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: size
    wrapMode: wrap ? Text.WordWrap : Text.NoWrap
  }

  component DpiButton: Button {
    foreground: root.foreground
    accent: root.accent
    fontFamily: root.fontFamily
    fontSize: Style.font.body
    horizontalPadding: Style.spacing.controlPaddingX
    verticalPadding: Style.spacing.controlPaddingY
    opacity: enabled ? 1 : 0.55
  }

  component SwitchCard: BorderSurface {
    id: card
    property string title
    property string detail
    property bool isOn
    property bool attention: false
    property bool busy: false
    property color accentColor: root.accent
    signal toggled()

    width: parent.width
    implicitHeight: cardRow.implicitHeight + Style.space(22)
    color: Style.normalFillFor(root.foreground, root.accent)
    borderSpec: Border.flat(Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.14), 1)
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

        DpiText {
          text: card.title
          color: root.foreground
          size: Style.font.subtitle
          font.bold: true
        }

        DpiText {
          Layout.fillWidth: true
          text: card.detail
          color: card.attention ? root.urgent : root.dim
          wrap: true
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

  // ------------------------------------------------------------------- bar
  WidgetButton {
    id: barButton
    anchors.fill: parent
    bar: root.bar
    text: "DPI"
    fontSize: Style.font.bodySmall
    horizontalMargin: 8
    verticalPadding: 8
    active: root.running
    activeColor: root.failed ? root.urgent : root.accent
    dimmed: root.reachable && !root.running && !root.failed
    tooltipText: root.tooltip

    onPressed: function(button) {
      if (button === Qt.RightButton) root.toggleBypass()
      else if (button === Qt.MiddleButton) root.runCheck()
      else root.toggle()
    }
  }

  // ----------------------------------------------------------------- popup
  KeyboardPanel {
    id: popup
    anchorItem: barButton
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keys
    contentWidth: popup.fittedContentWidth(Style.space(360))
    contentHeight: popup.fittedContentHeight(body.implicitHeight, Style.space(560))

    PanelKeyCatcher {
      id: keys
      anchors.fill: parent
      onCloseRequested: root.close()
      onActivateRequested: root.toggleBypass()
      onTextKey: function(text) {
        if (text === "r" || text === "R") root.refresh()
        else if (text === "c" || text === "C") root.runCheck()
        else if (text === "g" || text === "G") root.runGenerate()
        else if (text === "w" || text === "W") root.toggleWarp()
      }

      Flickable {
        id: flick
        anchors.fill: parent
        contentWidth: width
        contentHeight: body.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: body
          width: flick.width
          spacing: Style.space(12)

          // ------------------------------------------------------- header
          Row {
            width: parent.width
            spacing: Style.space(10)

            DpiIcon {
              width: Style.space(30)
              height: Style.space(30)
              anchors.verticalCenter: parent.verticalCenter
              color: root.foreground
              accent: root.failed ? root.urgent : root.accent
              filled: root.running
            }

            Column {
              width: parent.width - 30 - refreshButton.width - Style.space(20)
              anchors.verticalCenter: parent.verticalCenter
              spacing: 1

              DpiText {
                text: "DPI Pilot"
                color: root.foreground
                size: Style.font.title
                font.bold: true
              }

              DpiText {
                width: parent.width
                text: root.stateText + (root.strategyName !== "" ? " · " + root.strategyName : "")
                color: root.failed ? root.urgent : root.dim
                elide: Text.ElideRight
              }
            }

            DpiButton {
              id: refreshButton
              anchors.verticalCenter: parent.verticalCenter
              iconText: "󰑐"
              iconSpinning: statusProc.running || root.busy
              tooltipText: "Обновить (R)"
              iconSize: Style.font.subtitle
              horizontalPadding: Style.space(4)
              verticalPadding: Style.space(3)
              onClicked: root.refresh()
            }
          }

          // ------------------------------------------------------ install
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.reachable && !root.installed

            DpiText {
              width: parent.width
              text: "Движок zapret2 ещё не установлен. Установка скачает официальный релиз bol-van/zapret2 и один раз попросит пароль."
              size: Style.font.bodySmall
              wrap: true
            }

            DpiButton {
              width: parent.width
              text: root.busy ? root.actionLabel : "Установить"
              iconText: "󰇚"
              bordered: true
              active: true
              enabled: !root.busy
              onClicked: root.installEngine()
            }
          }

          // -------------------------------------------------------- switch
          SwitchCard {
            visible: root.installed
            title: "Обход DPI"
            detail: root.failed ? "Служба не запустилась — смотрите журнал"
              : root.running ? "Трафик идёт через nfqws2"
              : "Готов включить подобранную стратегию"
            isOn: root.running
            attention: root.failed
            busy: root.busy || root.generating
            accentColor: root.failed ? root.urgent : root.accent
            onToggled: root.toggleBypass()
          }

          // ----------------------------------------------------------- warp
          SwitchCard {
            visible: root.installed
            title: "WARP"
            detail: root.warpText
            isOn: root.warpRunning
            attention: root.warp.failed === true
            busy: root.busy || root.generating
            accentColor: root.warpConflict !== "" ? root.faint : root.accent
            onToggled: root.toggleWarp()
          }

          // -------------------------------------------------------- check
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.installed

            Row {
              width: parent.width

              PanelSectionHeader {
                text: "ДОСТУПНОСТЬ"
                foreground: root.foreground
                fontFamily: root.fontFamily
                anchors.verticalCenter: parent.verticalCenter
              }

              Item { width: Math.max(0, parent.width - parent.children[0].implicitWidth - ageText.implicitWidth); height: 1 }

              DpiText {
                id: ageText
                text: root.whenText()
                color: root.faint
                anchors.verticalCenter: parent.verticalCenter
              }
            }

            Row {
              width: parent.width
              spacing: Style.space(14)

              Repeater {
                model: [
                  { key: "youtube", label: "YouTube" },
                  { key: "discord", label: "Discord" },
                  { key: "google", label: "Google" }
                ]

                Row {
                  required property var modelData
                  spacing: Style.space(6)
                  anchors.verticalCenter: parent.verticalCenter

                  readonly property var result: root.findResult(modelData.key)

                  Rectangle {
                    width: Style.space(7)
                    height: width
                    radius: width / 2
                    anchors.verticalCenter: parent.verticalCenter
                    color: parent.result === null ? "transparent"
                      : parent.result.ok ? root.accent : root.urgent
                    border.color: parent.result === null ? root.faint : "transparent"
                    border.width: parent.result === null ? 1 : 0
                  }

                  DpiText {
                    text: modelData.label
                    color: parent.result === null ? root.dim : root.foreground
                    size: Style.font.bodySmall
                    anchors.verticalCenter: parent.verticalCenter
                  }
                }
              }
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              DpiButton {
                Layout.fillWidth: true
                width: (parent.width - parent.spacing) * 0.58
                text: root.actionName === "generate" ? "Подбор…" : "Подобрать"
                iconText: "󰒓"
                bordered: true
                active: true
                enabled: !root.busy && !root.generating
                tooltipText: "Собрать стратегии, проверить их и оставить лучшую (G)"
                onClicked: root.runGenerate()
              }

              DpiButton {
                width: parent.width - (parent.width - parent.spacing) * 0.58 - parent.spacing
                text: root.actionName === "check" ? "Проверка…" : "Проверить"
                bordered: true
                enabled: !root.busy && !root.generating
                tooltipText: "Проверить текущее состояние (C)"
                onClicked: root.runCheck()
              }
            }
          }

          // ----------------------------------------------------- progress
          Column {
            width: parent.width
            spacing: Style.space(6)
            visible: root.generating

            Row {
              width: parent.width

              DpiText {
                text: "Подбор стратегий"
                color: root.foreground
                size: Style.font.bodySmall
                font.bold: true
              }

              Item { width: Math.max(0, parent.width - parent.children[0].implicitWidth - countText.implicitWidth); height: 1 }

              DpiText {
                id: countText
                text: (root.progress.done || 0) + " / " + (root.progress.total || 0)
              }
            }

            Rectangle {
              width: parent.width
              height: Style.space(4)
              radius: height / 2
              color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.12)

              Rectangle {
                width: parent.width * Math.max(0, Math.min(1,
                  (root.progress.done || 0) / Math.max(1, root.progress.total || 1)))
                height: parent.height
                radius: parent.radius
                color: root.accent
                Behavior on width { NumberAnimation { duration: 240; easing.type: Easing.OutCubic } }
              }
            }

            DpiText {
              width: parent.width
              text: root.progress.current ? root.progress.current : "готовим первую стратегию…"
              elide: Text.ElideRight
            }
          }

          // ---------------------------------------------------- strategies
          Column {
            width: parent.width
            spacing: Style.space(6)
            visible: root.installed && !root.generating && root.strategies.length > 1

            PanelSectionHeader {
              text: "СОХРАНЁННЫЕ"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Repeater {
              model: root.strategies.slice(0, 3)

              DpiButton {
                required property var modelData
                width: body.width
                leftAlign: true
                bordered: modelData.id === root.activeId
                selected: modelData.id === root.activeId
                text: modelData.name + "  ·  " + modelData.passed + "/" + modelData.total
                fontSize: Style.font.bodySmall
                horizontalPadding: Style.space(8)
                verticalPadding: Style.space(5)
                onClicked: root.useStrategy(modelData.id)
              }
            }
          }

          // ------------------------------------------------------- notices
          DpiText {
            width: parent.width
            visible: root.errorText !== ""
            text: root.errorText
            color: root.urgent
            wrap: true
          }

          DpiText {
            width: parent.width
            visible: root.conflict && root.installed
            text: "Одновременно работает omarchy-zapret2. Оставьте включённым только один обход: два nfqws2 перехватывают одни и те же пакеты."
            wrap: true
          }

          DpiText {
            width: parent.width
            visible: root.flashText !== ""
            text: root.flashText
            color: root.accent
            wrap: true
          }

          // ------------------------------------------------------ advanced
          Column {
            width: parent.width
            spacing: Style.space(6)
            visible: root.installed

            PanelSeparator { foreground: root.foreground }

            DpiButton {
              width: parent.width
              leftAlign: true
              bordered: false
              text: root.advanced ? "Свернуть" : "Дополнительно"
              foreground: root.dim
              fontSize: Style.font.bodySmall
              horizontalPadding: 0
              verticalPadding: Style.space(2)
              onClicked: root.advanced = !root.advanced
            }

            Column {
              width: parent.width
              spacing: Style.space(6)
              visible: root.advanced

              DpiText {
                width: parent.width
                text: "Движок: " + (root.engine !== "" ? root.engine : "—")
                  + " · nfqws2 · очередь " + 230
                wrap: true
              }

              DpiText {
                width: parent.width
                text: "Обход применяется ко всему трафику — списки и исключения не нужны. Если что-то не работает: journalctl -u kich-dpi -f"
                color: root.faint
                wrap: true
              }

              DpiButton {
                width: parent.width
                leftAlign: true
                bordered: true
                text: "Обновить движок"
                enabled: !root.busy
                fontSize: Style.font.bodySmall
                horizontalPadding: Style.space(8)
                verticalPadding: Style.space(5)
                onClicked: root.updateEngine()
              }

              DpiButton {
                width: parent.width
                leftAlign: true
                bordered: true
                text: root.armRemove ? "Точно удалить?" : "Удалить движок"
                enabled: !root.busy
                foreground: root.armRemove ? root.urgent : root.foreground
                fontSize: Style.font.bodySmall
                horizontalPadding: Style.space(8)
                verticalPadding: Style.space(5)
                onClicked: root.removeEngine()
              }
            }
          }
        }
      }
    }
  }
}
