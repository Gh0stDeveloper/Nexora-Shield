package dev.nexora.shield.studio.ui

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StudioUxPolicyTest {
    @Test
    fun responsiveThresholdsAreDeterministic() {
        assertTrue(StudioLayoutPolicy.useCompactNavigation(1179f))
        assertFalse(StudioLayoutPolicy.useCompactNavigation(1180f))
        assertTrue(StudioLayoutPolicy.useCompactContent(1079f))
        assertFalse(StudioLayoutPolicy.useCompactContent(1080f))
    }

    @Test
    fun minimumDesktopViewportRemainsUsable() {
        assertTrue(StudioLayoutPolicy.minimumWindowWidthPx >= 960)
        assertTrue(StudioLayoutPolicy.minimumWindowHeightPx >= 640)
    }

    @Test
    fun feedbackClassificationPrioritizesActiveWorkAndErrors() {
        assertEquals(
            FeedbackLevel.Working,
            StudioFeedbackPolicy.classify("Previous operation failed.", busy = true),
        )
        assertEquals(
            FeedbackLevel.Error,
            StudioFeedbackPolicy.classify("Artifact verification failed.", busy = false),
        )
        assertEquals(
            FeedbackLevel.Success,
            StudioFeedbackPolicy.classify("Configuration saved.", busy = false),
        )
        assertEquals(
            FeedbackLevel.Neutral,
            StudioFeedbackPolicy.classify("Import an Android project to begin.", busy = false),
        )
    }
}
