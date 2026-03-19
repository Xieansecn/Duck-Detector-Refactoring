package com.eltavine.duckdetector.ui.shell

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import com.eltavine.duckdetector.core.ui.components.WrapSafeText

internal const val NON_OK_RESULT_NOTICE =
    "Think independently and distinguish right from wrong. Detector is merely an ordinary app; practice is the sole criterion for testing truth."

internal fun shouldShowDetectorResultNotice(
    isLoading: Boolean,
    overviewHeadline: String,
): Boolean {
    return !isLoading && !overviewHeadline.equals("OK", ignoreCase = true)
}

@Composable
fun DetectorResultNoticeDialog(
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            WrapSafeText(
                text = "Reminder",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        },
        text = {
            WrapSafeText(
                text = NON_OK_RESULT_NOTICE,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                WrapSafeText(
                    text = "Continue",
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
    )
}
