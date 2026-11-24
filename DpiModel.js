// Pure helpers for the DPI Pilot panel. No QML state, no processes: just the
// formatting and command-result rules, so they can be tested with plain Node.

function compactAddress(value) {
  var text = String(value || "")
  if (text.indexOf(":") < 0 || text.length <= 24) return text
  var parts = text.split(":")
  return parts.slice(0, 3).join(":") + "…" + parts.slice(-2).join(":")
}

function warpCheckText(check, now) {
  if (!check || !check.time) return ""
  if (now / 1000 - check.time > 900) return ""
  return check.ok && check.ip ? compactAddress(check.ip) : ""
}

function warpText(warp, checkText) {
  if (!warp || warp.available !== true) return "mihomo не установлен — нажмите, чтобы доустановить"
  if (warp.running === true) {
    if (checkText !== "") {
      var route = warp.check && warp.check.tun === false ? " · маршрут не в туннеле" : ""
      return "Выход " + checkText + (warp.check && warp.check.colo ? " · " + warp.check.colo : "") + route
    }
    return "Туннель включён"
  }
  if (warp.failed === true) return "Служба не запустилась — смотрите журнал"
  if (warp.registered === true) return "Готов включить туннель"
  return "Аккаунт Cloudflare создастся при включении"
}

function stateText(reachable, installed, failed, running) {
  if (!reachable) return "нет связи"
  if (!installed) return "не установлен"
  if (failed) return "ошибка"
  if (running) return "включён"
  return "выключен"
}

function shortError(text) {
  var value = String(text || "").split("\n")[0]
  return value.length > 120 ? value.substring(0, 117) + "…" : value
}

function whenText(check, now) {
  if (!check || !check.time) return "ещё не проверялось"
  var minutes = Math.floor((now / 1000 - check.time) / 60)
  if (minutes < 1) return "только что"
  if (minutes < 60) return minutes + " мин назад"
  return Math.floor(minutes / 60) + " ч назад"
}

function checkText(check) {
  if (!check || !check.total) return "проверок ещё не было"
  return "Доступно " + check.passed + "/" + check.total + " · " + whenText(check, Date.now())
}

function progressText(progress) {
  if (!progress || !progress.running) return ""
  return "Подбор " + progress.done + "/" + progress.total + " · " + (progress.current || "")
}

function findResult(results, key) {
  var rows = results || []
  for (var i = 0; i < rows.length; i++) {
    if (rows[i] && rows[i].key === key) return rows[i]
  }
  return null
}

function recentCheck(check, now, maxAge) {
  if (!check || !check.time) return false
  var stamp = typeof now === "number" ? now : Date.now()
  return stamp / 1000 - Number(check.time) <= (maxAge || 900)
}

function wantedFlag(status, key) {
  var wanted = status && status.wanted
  // Older installed CLIs had no `wanted` field: a running service was wanted.
  return !wanted || wanted[key] !== false
}

function dpiUnhealthy(status, now) {
  if (!status || status.installed !== true || !wantedFlag(status, "dpi")) return false
  if (status.failed === true || status.running !== true) return true
  var check = status.check || {}
  return recentCheck(check, now) && Number(check.total) > 0 &&
    Number(check.passed) < Number(check.total)
}

function warpUnhealthy(status, now) {
  if (!status || status.installed !== true || !wantedFlag(status, "warp")) return false
  var warp = status.warp || {}
  if (warp.available !== true || warp.failed === true || warp.running !== true) return true
  var check = warp.check || {}
  return recentCheck(check, now) && check.ok === false
}

function hasProblem(status, now) {
  return dpiUnhealthy(status, now) || warpUnhealthy(status, now)
}

// One compact line for one diagnostic button. It follows the desired state:
// a service the user switched off is simply not part of the check.
function diagnosticLine(status, summary) {
  if (!status || status.installed !== true)
    return "Проверки доступны после установки движка"
  var parts = []
  if (wantedFlag(status, "dpi")) {
    var dpi = summary && summary.check ? summary.check : status.check
    parts.push(dpi && Number(dpi.total)
      ? "DPI " + dpi.passed + "/" + dpi.total : "DPI —")
  }
  if (wantedFlag(status, "warp")) {
    var tunnel = summary && summary.warp_check
      ? summary.warp_check : (status.warp && status.warp.check)
    parts.push(tunnel && tunnel.time
      ? "WARP " + (tunnel.ok ? "ok" : "ошибка") : "WARP —")
  }
  if (summary && summary.doctor)
    parts.push("Система " + summary.doctor.passed + "/" + summary.doctor.total)
  return parts.join(" · ") || "Проверок ещё не было"
}

// The three failure kinds are described once here. Both the header flag and
// the error line are derived from the same list, so they cannot drift apart.
function diagnosticIssueParts(summary) {
  var parts = []
  if (!summary) return parts
  var dpi = summary.check
  if (dpi && Number(dpi.total) && Number(dpi.passed) < Number(dpi.total))
    parts.push("DPI " + dpi.passed + "/" + dpi.total)
  var tunnel = summary.warp_check
  if (tunnel && tunnel.time && tunnel.ok === false)
    parts.push("WARP: " + (shortError(tunnel.error) || "ошибка"))
  var system = summary.doctor
  if (system && system.failed && system.failed.length)
    parts.push("Система: " + system.failed.join(", "))
  return parts
}

function diagnosticProblem(summary) {
  return diagnosticIssueParts(summary).length > 0
}

function diagnosticError(summary) {
  return diagnosticIssueParts(summary).join(" · ")
}

// Every finished command is translated here. QML only applies the decision.
function actionResult(name, parsed, code, err) {
  var result = {
    error: "", flash: "", reuseStatus: false, reuseWarp: null,
    followUpWarpCheck: false, advanced: false, refresh: true, checkAll: null,
  }

  if (code === 126 || code === 127) {
    result.error = code === 126 ? "Отменено" : "Не найден pkexec"
    result.refresh = false
    return result
  }
  if (parsed && parsed.ok === false) {
    result.error = parsed.error || "Не удалось выполнить"
    result.refresh = false
    return result
  }
  if (code !== 0) {
    result.error = shortError(err) || ("Код " + code)
    result.refresh = false
    return result
  }

  if (name === "toggle") {
    if (parsed && parsed.ok === true && parsed.installed !== undefined) {
      result.reuseStatus = true
      result.refresh = false
    }
  } else if (name === "generate") {
    if (parsed && parsed.error) result.error = parsed.error
    else if (parsed && parsed.best) {
      result.flash = "Лучшая: " + parsed.best.name + " · " + parsed.best.passed + "/" + parsed.best.total
    } else result.flash = "Подбор завершён"
  } else if (name === "check") {
    result.flash = parsed && parsed.check
      ? "Проверено: " + parsed.check.passed + "/" + parsed.check.total
      : "Проверка завершена"
  } else if (name === "repair") {
    result.flash = parsed && parsed.fixes && parsed.fixes.length
      ? "Исправлено: " + parsed.fixes.join(" · ")
      : "Всё уже работает — поломок не найдено"
    if (parsed && parsed.blocked && parsed.blocked.length)
      result.error = parsed.blocked.join(" · ")
  } else if (name === "install" || name === "update") {
    result.flash = name === "install" ? "Движок установлен" : "Движок обновлён"
    if (parsed && parsed.warp === false && parsed.warp_note)
      result.error = "mihomo: " + parsed.warp_note
  } else if (name === "warp") {
    if (parsed && parsed.warp) {
      result.reuseWarp = parsed.warp
      result.refresh = false
      if (parsed.warp.running === true) {
        result.flash = "WARP подключён"
        result.followUpWarpCheck = true
      } else result.flash = "WARP отключён"
    } else result.flash = "WARP отключён"
  } else if (name === "warp-check") {
    if (parsed && parsed.check && parsed.check.ok) {
      result.flash = "WARP работает" + (parsed.check.ip ? " · " + compactAddress(parsed.check.ip) : "")
    } else {
      result.error = parsed && parsed.check && parsed.check.error
        ? parsed.check.error : "WARP не подтвердился"
    }
  } else if (name === "warp-register") {
    result.flash = parsed && parsed.name ? "WARP: " + parsed.name : "WARP перерегистрирован"
  } else if (name === "use") {
    result.flash = parsed && parsed.active_name
      ? "Стратегия: " + parsed.active_name : "Стратегия применена"
  } else if (name === "doctor") {
    result.flash = "Диагностика обновлена"
  } else if (name === "check-all") {
    result.checkAll = parsed || {}
    result.error = diagnosticError(parsed)
    result.flash = result.error !== "" ? "Есть проблемы" : "Всё проверено"
  } else if (name === "remove") {
    result.advanced = true
    result.flash = "Системная часть удалена"
  }
  return result
}

// One table for IPC and button actions, so keybinds cannot drift from the UI.
function invoke(target, name) {
  if (!target) return
  if (name === "service" || name === "toggle") target.toggleBypass()
  else if (name === "warp") target.toggleWarp()
  else if (name === "check") target.runDiagnostics()
  else if (name === "doctor") target.runDoctor()
  else if (name === "warp-check") target.checkWarp()
  else if (name === "generate") target.runGenerate()
  else if (name === "repair") target.runRepair()
  else if (name === "refresh") target.refresh()
}

if (typeof module !== "undefined") {
  module.exports = {
    compactAddress: compactAddress, warpCheckText: warpCheckText,
    warpText: warpText, stateText: stateText, shortError: shortError,
    whenText: whenText, checkText: checkText, progressText: progressText,
    findResult: findResult, recentCheck: recentCheck,
    dpiUnhealthy: dpiUnhealthy, warpUnhealthy: warpUnhealthy,
    hasProblem: hasProblem, diagnosticLine: diagnosticLine,
    diagnosticProblem: diagnosticProblem, diagnosticError: diagnosticError,
    actionResult: actionResult, invoke: invoke,
  }
}
