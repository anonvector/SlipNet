package app.slipnet.presentation.navigation

import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import app.slipnet.presentation.home.HomeScreen
import app.slipnet.presentation.profiles.EditProfileScreen
import app.slipnet.presentation.profiles.ProfileListScreen
import app.slipnet.presentation.settings.SettingsScreen

@Composable
fun NavGraph(
    navController: NavHostController,
    modifier: Modifier = Modifier
) {
    NavHost(
        navController = navController,
        startDestination = NavRoutes.Home.route,
        modifier = modifier,
        enterTransition = { EnterTransition.None },
        exitTransition = { ExitTransition.None },
        popEnterTransition = { EnterTransition.None },
        popExitTransition = { ExitTransition.None }
    ) {
        composable(NavRoutes.Home.route) {
            HomeScreen(
                onNavigateToProfiles = {
                    navController.navigate(NavRoutes.Profiles.route)
                },
                onNavigateToSettings = {
                    navController.navigate(NavRoutes.Settings.route)
                }
            )
        }

        composable(NavRoutes.Profiles.route) {
            ProfileListScreen(
                onNavigateBack = {
                    navController.popBackStack()
                },
                onNavigateToAddProfile = {
                    navController.navigate(NavRoutes.AddProfile.route)
                },
                onNavigateToEditProfile = { profileId ->
                    navController.navigate(NavRoutes.EditProfile.createRoute(profileId))
                }
            )
        }

        composable(NavRoutes.AddProfile.route) {
            EditProfileScreen(
                profileId = null,
                onNavigateBack = {
                    navController.popBackStack()
                }
            )
        }

        composable(
            route = NavRoutes.EditProfile.route,
            arguments = listOf(
                navArgument("profileId") { type = NavType.LongType }
            )
        ) { backStackEntry ->
            val profileId = backStackEntry.arguments?.getLong("profileId")
            EditProfileScreen(
                profileId = profileId,
                onNavigateBack = {
                    navController.popBackStack()
                }
            )
        }

        composable(NavRoutes.Settings.route) {
            SettingsScreen(
                onNavigateBack = {
                    navController.popBackStack()
                }
            )
        }
    }
}
