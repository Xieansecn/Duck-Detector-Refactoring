package com.eltavine.duckdetector.ui.shell

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectorResultNoticeDialogTest {

    @Test
    fun `does not show while dashboard is loading`() {
        assertFalse(
            shouldShowDetectorResultNotice(
                isLoading = true,
                overviewHeadline = "Danger",
            ),
        )
    }

    @Test
    fun `does not show when overall result is ok`() {
        assertFalse(
            shouldShowDetectorResultNotice(
                isLoading = false,
                overviewHeadline = "OK",
            ),
        )
    }

    @Test
    fun `shows when scan is complete and result is not ok`() {
        assertTrue(
            shouldShowDetectorResultNotice(
                isLoading = false,
                overviewHeadline = "Warning",
            ),
        )
    }
}
