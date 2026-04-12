package app.slipnet.presentation.common.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import app.slipnet.BuildConfig

@Composable
fun AboutDialogContent() {
    val uriHandler = LocalUriHandler.current

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(
            text = "SlipNet VPN v${BuildConfig.VERSION_NAME}",
            style = MaterialTheme.typography.titleMedium
        )
        Text(
            text = "A free, source-available anti-censorship VPN tool designed to bypass internet restrictions. SlipNet tunnels your traffic through DNS, SSH, Tor, and other protocols to keep you connected when access is blocked.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))

        // GitHub
        Text(
            text = "GitHub",
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary
        )
        Text(
            text = "github.com/anonvector/SlipNet",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.clickable {
                uriHandler.openUri("https://github.com/anonvector/SlipNet")
            }
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))

        // Telegram
        Text(
            text = "Telegram",
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary
        )
        Text(
            text = "t.me/SlipNet_app",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.clickable {
                uriHandler.openUri("https://t.me/SlipNet_app")
            }
        )


    }
}
