package app.slipnet.presentation.navigation

sealed class NavRoutes(val route: String) {
    data object Home : NavRoutes("home")
    data object Profiles : NavRoutes("profiles")
    data object AddProfile : NavRoutes("add_profile")
    data object EditProfile : NavRoutes("edit_profile/{profileId}") {
        fun createRoute(profileId: Long) = "edit_profile/$profileId"
    }
    data object Settings : NavRoutes("settings")
    data object DnsScanner : NavRoutes("dns_scanner?profileId={profileId}&fromProfile={fromProfile}") {
        fun createRoute(profileId: Long? = null, fromProfile: Boolean = false): String {
            val params = mutableListOf<String>()
            if (profileId != null) params.add("profileId=$profileId")
            if (fromProfile) params.add("fromProfile=true")
            return if (params.isEmpty()) "dns_scanner" else "dns_scanner?${params.joinToString("&")}"
        }
    }
    data object ScanResults : NavRoutes("scan_results?profileId={profileId}&fromProfile={fromProfile}") {
        fun createRoute(profileId: Long? = null, fromProfile: Boolean = false): String {
            val params = mutableListOf<String>()
            if (profileId != null) params.add("profileId=$profileId")
            if (fromProfile) params.add("fromProfile=true")
            return if (params.isEmpty()) "scan_results" else "scan_results?${params.joinToString("&")}"
        }
    }
}
