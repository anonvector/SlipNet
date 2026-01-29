package app.slipnet.presentation.common.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.slipnet.domain.model.ConnectionState
import app.slipnet.presentation.theme.ConnectedGreen
import app.slipnet.presentation.theme.ConnectingOrange
import app.slipnet.presentation.theme.DisconnectedRed

@Composable
fun VpnStatusCard(
    connectionState: ConnectionState,
    modifier: Modifier = Modifier
) {
    val statusColor by animateColorAsState(
        targetValue = when (connectionState) {
            is ConnectionState.Connected -> ConnectedGreen
            is ConnectionState.Connecting, is ConnectionState.Disconnecting -> ConnectingOrange
            is ConnectionState.Error -> DisconnectedRed
            is ConnectionState.Disconnected -> MaterialTheme.colorScheme.surfaceVariant
        },
        animationSpec = tween(300),
        label = "statusColor"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Status indicator
            StatusIndicator(
                connectionState = connectionState,
                statusColor = statusColor
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Status text
            Text(
                text = connectionState.displayName,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            // Profile name if connected
            if (connectionState is ConnectionState.Connected) {
                Text(
                    text = connectionState.profile.name,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Error message
            if (connectionState is ConnectionState.Error) {
                Text(
                    text = connectionState.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = DisconnectedRed
                )
            }
        }
    }
}

@Composable
private fun StatusIndicator(
    connectionState: ConnectionState,
    statusColor: Color,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .size(80.dp)
            .clip(CircleShape)
            .background(statusColor.copy(alpha = 0.2f)),
        contentAlignment = Alignment.Center
    ) {
        when (connectionState) {
            is ConnectionState.Connected -> {
                Icon(
                    imageVector = Icons.Default.Check,
                    contentDescription = "Connected",
                    modifier = Modifier.size(40.dp),
                    tint = statusColor
                )
            }
            is ConnectionState.Connecting, is ConnectionState.Disconnecting -> {
                CircularProgressIndicator(
                    modifier = Modifier.size(40.dp),
                    color = statusColor,
                    strokeWidth = 4.dp
                )
            }
            is ConnectionState.Error -> {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = "Error",
                    modifier = Modifier.size(40.dp),
                    tint = statusColor
                )
            }
            is ConnectionState.Disconnected -> {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = "Disconnected",
                    modifier = Modifier.size(40.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
