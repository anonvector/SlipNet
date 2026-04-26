package app.slipnet.presentation.common.icons

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

val VlessIcon: ImageVector
    get() {
        if (_vlessIcon != null) return _vlessIcon!!
        _vlessIcon = ImageVector.Builder(
            name = "Vless",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 192f,
            viewportHeight = 192f
        ).apply {
            path(
                stroke = SolidColor(Color.Black),
                strokeLineWidth = 12f,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round
            ) {
                moveTo(22f, 39.005f)
                horizontalLineToRelative(40.738f)
                verticalLineToRelative(113.99f)
                lineTo(170f, 39.005f)
            }
        }.build()
        return _vlessIcon!!
    }

private var _vlessIcon: ImageVector? = null
