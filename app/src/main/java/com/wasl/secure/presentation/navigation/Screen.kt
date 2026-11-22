package com.wasl.secure.presentation.navigation

sealed class Screen(val route: String) {
    object ChatsList : Screen("chats_list")
    object Conversation : Screen("conversation/{conversationId}") {
        fun createRoute(conversationId: String) = "conversation/$conversationId"
    }
}
