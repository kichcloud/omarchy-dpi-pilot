import QtQuick

// A small shield with a lightning bolt, drawn rather than shipped as an SVG so
// it follows the bar foreground and accent without an asset pipeline.
Canvas {
  id: root

  property color color: "#ffffff"
  property color accent: "#ffffff"
  property bool filled: false

  antialiasing: true
  onColorChanged: requestPaint()
  onAccentChanged: requestPaint()
  onFilledChanged: requestPaint()
  onWidthChanged: requestPaint()
  onHeightChanged: requestPaint()

  onPaint: {
    var ctx = getContext("2d")
    var w = width
    var h = height
    ctx.clearRect(0, 0, w, h)
    ctx.lineWidth = Math.max(1.2, w * 0.075)
    ctx.lineJoin = "round"
    ctx.lineCap = "round"

    // Shield outline.
    ctx.beginPath()
    ctx.moveTo(w * 0.5, h * 0.08)
    ctx.lineTo(w * 0.84, h * 0.24)
    ctx.lineTo(w * 0.84, h * 0.52)
    ctx.quadraticCurveTo(w * 0.84, h * 0.78, w * 0.5, h * 0.94)
    ctx.quadraticCurveTo(w * 0.16, h * 0.78, w * 0.16, h * 0.52)
    ctx.lineTo(w * 0.16, h * 0.24)
    ctx.closePath()

    if (filled) {
      ctx.fillStyle = Qt.rgba(accent.r, accent.g, accent.b, 0.18)
      ctx.fill()
    }
    ctx.strokeStyle = color
    ctx.stroke()

    // Bolt.
    ctx.beginPath()
    ctx.moveTo(w * 0.54, h * 0.28)
    ctx.lineTo(w * 0.36, h * 0.55)
    ctx.lineTo(w * 0.48, h * 0.55)
    ctx.lineTo(w * 0.43, h * 0.74)
    ctx.lineTo(w * 0.64, h * 0.46)
    ctx.lineTo(w * 0.51, h * 0.46)
    ctx.closePath()
    ctx.fillStyle = filled ? accent : color
    ctx.fill()
  }
}
