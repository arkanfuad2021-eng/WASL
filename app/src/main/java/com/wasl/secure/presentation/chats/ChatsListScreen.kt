package com.wasl.secure.presentation.chats

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wasl.secure.R
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack
import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.presentation.chats.components.ChatItemRow

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatsListScreen(
    conversations: List<Conversation>,
    isDarkTheme: Boolean,
    onToggleTheme: () -> Unit,
    onChatClick: (String) -> Unit,
    onNewChatClick: () -> Unit,
    onDeleteChat: (String) -> Unit
) {
    val customColors = LocalWaslColors.current
    var selectedConversationForAction by remember { mutableStateOf<Conversation?>(null) }
    var isSearching by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }

    val filteredConversations = remember(conversations, searchQuery) {
        if (searchQuery.isBlank()) {
            conversations
        } else {
            conversations.filter {
                it.contactName.contains(searchQuery, ignoreCase = true) ||
                        it.phoneNumber.contains(searchQuery)
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    if (isSearching) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            placeholder = { Text("بحث بالاسم أو الرقم...") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )
                    } else {
                        Box(modifier = Modifier.fillMaxWidth()) {
                            Text(
                                text = "WASL | وَصْل",
                                fontFamily = ThmanyahBlack,
                                fontSize = 20.sp,
                                color = customColors.textPrimary
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = {
                        isSearching = !isSearching
                        if (!isSearching) searchQuery = ""
                    }) {
                        Icon(
                            imageVector = if (isSearching) Icons.Default.Close else Icons.Default.Search,
                            contentDescription = "Search",
                            tint = customColors.textSecondary
                        )
                    }
                    IconButton(onClick = onToggleTheme) {
                        Icon(
                            imageVector = if (isDarkTheme) Icons.Default.LightMode else Icons.Default.DarkMode,
                            contentDescription = "Toggle Theme",
                            tint = customColors.textSecondary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onNewChatClick,
                containerColor = customColors.sentBubble,
                contentColor = Color.White,
                shape = RoundedCornerShape(16.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Add,
                    contentDescription = "New Encrypted Chat",
                    modifier = Modifier.size(26.dp)
                )
            }
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            if (filteredConversations.isEmpty()) {
                // Clean empty state
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Spacer(modifier = Modifier.weight(1f))
                    Box(
                        modifier = Modifier
                            .size(72.dp)
                            .background(
                                customColors.sentBubble.copy(alpha = 0.1f),
                                RoundedCornerShape(24.dp)
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "🔒",
                            fontSize = 32.sp
                        )
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = if (searchQuery.isNotBlank()) "لا توجد نتائج مطابقة للبحث" else stringResource(R.string.no_chats_yet),
                        style = MaterialTheme.typography.titleMedium,
                        color = customColors.textPrimary
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = if (searchQuery.isNotBlank()) "تحقق من صحة الاسم أو رقم الهاتف" else stringResource(R.string.start_new_chat),
                        style = MaterialTheme.typography.bodyMedium,
                        color = customColors.textSecondary
                    )
                    Spacer(modifier = Modifier.height(20.dp))
                    if (searchQuery.isBlank()) {
                        Button(
                            onClick = onNewChatClick,
                            colors = ButtonDefaults.buttonColors(containerColor = customColors.sentBubble),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text("بدء محادثة مشفرة جديدة")
                        }
                    }
                    Spacer(modifier = Modifier.weight(1.5f))
                }
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(filteredConversations, key = { it.id }) { conversation ->
                        ChatItemRow(
                            conversation = conversation,
                            onClick = { onChatClick(conversation.id) },
                            onLongClick = { selectedConversationForAction = conversation }
                        )
                        Divider(
                            color = customColors.divider,
                            thickness = 0.5.dp,
                            modifier = Modifier.padding(horizontal = 16.dp)
                        )
                    }
                }
            }
        }
    }

    // Long-press Action Dialog (Delete / Select)
    selectedConversationForAction?.let { conversation ->
        AlertDialog(
            onDismissRequest = { selectedConversationForAction = null },
            title = {
                Text(
                    text = conversation.contactName,
                    fontFamily = ThmanyahBlack,
                    color = customColors.textPrimary
                )
            },
            text = {
                Text(
                    text = "خيارات المحادثة المشفرة (${conversation.phoneNumber}):",
                    style = MaterialTheme.typography.bodyMedium,
                    color = customColors.textSecondary
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDeleteChat(conversation.id)
                        selectedConversationForAction = null
                    }
                ) {
                    Text(
                        text = "مسح المحادثة محلياً",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { selectedConversationForAction = null }) {
                    Text(
                        text = stringResource(R.string.return_button),
                        color = customColors.textPrimary,
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            },
            containerColor = MaterialTheme.colorScheme.surface
        )
    }
}
