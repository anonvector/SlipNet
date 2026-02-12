package app.slipnet.presentation.common.icons

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

val TorIcon: ImageVector
    get() {
        if (_torIcon != null) return _torIcon!!
        _torIcon = ImageVector.Builder(
            name = "TorBrowser",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 192f,
            viewportHeight = 192f
        ).apply {
            // Outer circle
            path(
                stroke = SolidColor(Color.Black),
                strokeLineWidth = 12f,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round
            ) {
                moveTo(96f, 170f)
                curveTo(136.869f, 170f, 170f, 136.869f, 170f, 96f)
                curveTo(170f, 55.13f, 136.869f, 22f, 96f, 22f)
                curveTo(55.13f, 22f, 22f, 55.13f, 22f, 96f)
                curveTo(22f, 136.869f, 55.13f, 170f, 96f, 170f)
                close()
            }
            // Middle right semicircle (radius 50)
            path(
                stroke = SolidColor(Color.Black),
                strokeLineWidth = 12f,
                strokeLineCap = StrokeCap.Round
            ) {
                moveTo(96f, 46f)
                arcToRelative(50f, 50f, 0f, isMoreThanHalf = true, isPositiveArc = true, dx1 = 0f, dy1 = 100f)
            }
            // Inner right semicircle (radius 26)
            path(
                stroke = SolidColor(Color.Black),
                strokeLineWidth = 12f,
                strokeLineCap = StrokeCap.Round
            ) {
                moveTo(96f, 70f)
                arcToRelative(26.003f, 26.003f, 0f, isMoreThanHalf = false, isPositiveArc = true, dx1 = 24.021f, dy1 = 16.05f)
                arcToRelative(26.012f, 26.012f, 0f, isMoreThanHalf = false, isPositiveArc = true, dx1 = 0f, dy1 = 19.9f)
                arcToRelative(26.023f, 26.023f, 0f, isMoreThanHalf = false, isPositiveArc = true, dx1 = -5.636f, dy1 = 8.435f)
                arcTo(26.015f, 26.015f, 0f, isMoreThanHalf = false, isPositiveArc = true, x1 = 96f, y1 = 122f)
            }
        }.build()
        return _torIcon!!
    }

private var _torIcon: ImageVector? = null
