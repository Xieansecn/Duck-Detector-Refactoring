package com.eltavine.duckdetector.features.virtualization.presentation

import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationReport
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationCardModel

enum class VirtualizationUiStage {
    LOADING,
    READY,
    FAILED,
}

data class VirtualizationUiState(
    val stage: VirtualizationUiStage,
    val report: VirtualizationReport,
    val cardModel: VirtualizationCardModel,
)
