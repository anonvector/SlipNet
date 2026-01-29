package app.slipnet.presentation.navigation

sealed class NavRoutes(val route: String) {
    data object Home : NavRoutes("home")
    data object Profiles : NavRoutes("profiles")
    data object AddProfile : NavRoutes("add_profile")
    data object EditProfile : NavRoutes("edit_profile/{profileId}") {
        fun createRoute(profileId: Long) = "edit_profile/$profileId"
    }
    data object Settings : NavRoutes("settings")
}
