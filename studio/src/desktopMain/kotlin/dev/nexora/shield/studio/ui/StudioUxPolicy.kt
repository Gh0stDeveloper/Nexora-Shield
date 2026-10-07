package dev.nexora.shield.studio.ui

object StudioLayoutPolicy {
    const val minimumWindowWidthPx = 980
    const val minimumWindowHeightPx = 680
    const val compactNavigationThresholdDp = 1180f
    const val compactContentThresholdDp = 1080f

    fun useCompactNavigation(widthDp: Float): Boolean =
        widthDp < compactNavigationThresholdDp

    fun useCompactContent(widthDp: Float): Boolean =
        widthDp < compactContentThresholdDp
}

enum class FeedbackLevel {
    Neutral,
    Working,
    Success,
    Error,
}

object StudioFeedbackPolicy {
    fun classify(message: String, busy: Boolean): FeedbackLevel = when {
        busy -> FeedbackLevel.Working
        message.contains("failed", ignoreCase = true) ||
            message.contains("error", ignoreCase = true) -> FeedbackLevel.Error
        message.contains("success", ignoreCase = true) ||
            message.contains("saved", ignoreCase = true) ||
            message.contains("imported", ignoreCase = true) ||
            message.contains("loaded", ignoreCase = true) ||
            message.contains("completed", ignoreCase = true) -> FeedbackLevel.Success
        else -> FeedbackLevel.Neutral
    }
}
