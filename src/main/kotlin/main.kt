package com.example   // ⚠️ 你的包名

import com.google.gson.Gson
import io.ktor.serialization.gson.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.jdbc.*
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import io.ktor.http.*
import io.ktor.server.http.content.staticFiles
import io.ktor.server.request.receiveMultipart
import io.ktor.http.content.PartData
import java.io.File
import io.ktor.utils.io.toByteArray

data class PostRequest(val content: String)
data class PostItem(val id: Int, val username: String, val content: String, val createdAt: Long)
data class PostPage(val list: List<PostItem>, val total: Long)
data class ChangePasswordRequest(val oldPassword: String, val newPassword: String)
data class MeResponse(val username: String)

data class AuthRequest(val username: String, val password: String)
data class AuthResponse(val success: Boolean, val message: String, val token: String? = null)

object ServerCrypto {
    private val random = SecureRandom()
    fun newSalt() = ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
    fun hash(password: String, salt: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest((salt + password).toByteArray())
            .joinToString("") { "%02x".format(it) }
}

object Users : Table("users") {
    val id = integer("id").autoIncrement()
    val username = varchar("username", 64).uniqueIndex()
    val salt = varchar("salt", 64)
    val passwordHash = varchar("password_hash", 128)
    override val primaryKey = PrimaryKey(id)
}

object Tokens : Table("tokens") {
    val token = varchar("token", 64)
    val username = varchar("username", 64)
    val expiresAt = long("expires_at")          // ← 新增：过期时间戳（毫秒）
    override val primaryKey = PrimaryKey(token)
}
object Posts : Table("posts") {
    val id = integer("id").autoIncrement()
    val username = varchar("username", 64)
    val content = varchar("content", 500)
    val createdAt = long("created_at")
    override val primaryKey = PrimaryKey(id)
}

fun initDb() {
    Database.connect("jdbc:sqlite:users.db", driver = "org.sqlite.JDBC")
    transaction {
        SchemaUtils.create(Users, Tokens, Posts)
    }
}

fun main() {
    System.setOut(java.io.PrintStream(System.out, true, "UTF-8"))
    System.setErr(java.io.PrintStream(System.err, true, "UTF-8"))
    initDb()
    embeddedServer(Netty, host = "127.0.0.1", port = 8081) {
        install(ContentNegotiation) { gson() }
        routing {
            post("/register") {
                val req = Gson().fromJson(call.receiveText(), AuthRequest::class.java)
                val result = transaction {
                    val exists = Users.selectAll().where { Users.username eq req.username }.count() > 0
                    when {
                        req.username.isBlank() -> "请输入用户名"
                        req.password.length < 6 -> "密码至少 6 位"
                        exists -> "用户名已存在"
                        else -> {
                            val salt = ServerCrypto.newSalt()
                            Users.insert {
                                it[username] = req.username
                                it[Users.salt] = salt
                                it[passwordHash] = ServerCrypto.hash(req.password, salt)
                            }
                            "注册成功"
                        }
                    }
                }
                call.respond(AuthResponse(result == "注册成功", result))
            }
            post("/login") {
                val req = Gson().fromJson(call.receiveText(), AuthRequest::class.java)
                val now = System.currentTimeMillis()
                var token: String? = null
                val message = transaction {
                    // ===== 惰性清理：登录时顺手删掉所有过期令牌 =====
                    Tokens.deleteWhere { Tokens.expiresAt lessEq now }

                    val row = Users.selectAll().where { Users.username eq req.username }.singleOrNull()
                    if (row != null && row[Users.passwordHash] == ServerCrypto.hash(req.password, row[Users.salt])) {
                        token = UUID.randomUUID().toString()
                        Tokens.insert {
                            it[Tokens.token] = token!!
                            it[username] = req.username
                            it[Tokens.expiresAt] = now + 7L * 24 * 60 * 60 * 1000   // ← 2 分钟后死亡
                        }
                        "登录成功"
                    } else "用户名或密码错误"
                }
                println(">>> 登录结果: $message, 令牌: ${token?.take(8)}... (2分钟后过期)")
                call.respond(AuthResponse(token != null, message, token))
            }
            post( path = "/logout") {
                val header = call.request.header("Authorization")
                if (header == null) {
                    call.respond(AuthResponse(false, "无效令牌"))
                } else {
                    val t: String = header
                    val now = System.currentTimeMillis()
                    val (success, msg) = transaction {
                        val row = Tokens.selectAll().where { Tokens.token eq t }.singleOrNull()
                        when {
                            row == null -> false to "无效令牌"
                            row[Tokens.expiresAt] <= now -> {
                                Tokens.deleteWhere { Tokens.token eq t }
                                false to "令牌已过期"
                            }
                            else -> (Tokens.deleteWhere { Tokens.token eq t } > 0) to "已退出"
                        }
                    }
                    println(">>> 退出登录: $msg"+"V2")  //测试
                    call.respond(AuthResponse(success, msg))
                }
            }

            post( path = "/change-password") {
                val header = call.request.header("Authorization")
                if (header == null) {
                    call.respond(io.ktor.http.HttpStatusCode.Unauthorized, AuthResponse(false, "未登录"))
                } else {
                    val req = Gson().fromJson(call.receiveText(), ChangePasswordRequest::class.java)
                    val now = System.currentTimeMillis()
                    val result = transaction {
                        val tokenRow = Tokens.selectAll().where { Tokens.token eq header }.singleOrNull()
                        when {
                            tokenRow == null -> "无效令牌"
                            tokenRow[Tokens.expiresAt] <= now -> {
                                Tokens.deleteWhere { Tokens.token eq header }
                                "令牌已过期"
                            }
                            req.newPassword.length < 6 -> "新密码至少 6 位"
                            else -> {
                                val username = tokenRow[Tokens.username]
                                val user = Users.selectAll().where { Users.username eq username }.singleOrNull()
                                if (user == null || user[Users.passwordHash] != ServerCrypto.hash(req.oldPassword, user[Users.salt])) {
                                    "原密码错误"
                                } else {
                                    val salt = ServerCrypto.newSalt()
                                    Users.update({ Users.username eq username }) {
                                        it[Users.salt] = salt
                                        it[passwordHash] = ServerCrypto.hash(req.newPassword, salt)
                                    }
                                    // 安全要点：改密后让所有设备下线
                                    Tokens.deleteWhere { Tokens.username eq username }
                                    "密码修改成功，请重新登录"
                                }
                            }
                        }
                    }
                    println(">>> 修改密码: $result")
                    call.respond(AuthResponse(result == "密码修改成功，请重新登录", result))
                }
            }

            // ===== 头像上传（multipart 文件）=====
            post( path = "/upload-avatar") {
                val header = call.request.header("Authorization")
                val now = System.currentTimeMillis()
                val username = if (header == null) null else transaction {
                    val r = Tokens.selectAll().where { Tokens.token eq header }.singleOrNull()
                    if (r != null && r[Tokens.expiresAt] > now) r[Tokens.username] else null
                }
                if (username == null) {
                    call.respond(io.ktor.http.HttpStatusCode.Unauthorized, AuthResponse(false, "未登录或令牌过期"))
                } else {
                    val multipart = call.receiveMultipart()
                    var savedName = ""
                    while (true) {
                        val part = multipart.readPart() ?: break
                        if (part is PartData.FileItem) {
                            val bytes = part.provider().toByteArray()
                            val ext = part.originalFileName?.substringAfterLast('.', "jpg") ?: "jpg"
                            File("avatars").mkdirs()
                            savedName = "$username.$ext"
                            File("avatars", savedName).writeBytes(bytes)
                        }
                    }
                    if (savedName.isNotEmpty()) {
                        println(">>> 头像上传: $savedName (${File("avatars", savedName).length()} 字节)")
                        call.respond(AuthResponse(true, "上传成功"))
                    } else {
                        call.respond(AuthResponse(false, "未收到文件"))
                    }
                }
            }



            // ===== 静态文件服务：/avatars/xxx.jpg 直接访问 =====
            staticFiles( remotePath = "/avatars", dir = File("avatars"))

            get( path = "/me") {
                val header = call.request.header("Authorization")
                if (header == null) {
                    call.respond(io.ktor.http.HttpStatusCode.Unauthorized, AuthResponse(false, "未登录"))
                } else {
                    val now = System.currentTimeMillis()
                    val username = transaction {
                        val tokenRow = Tokens.selectAll().where { Tokens.token eq header }.singleOrNull()
                        when {
                            tokenRow == null -> null
                            tokenRow[Tokens.expiresAt] <= now -> {
                                Tokens.deleteWhere { Tokens.token eq header }
                                null
                            }
                            else -> {
                                val userRow = Users.selectAll().where { Users.username eq tokenRow[Tokens.username] }.singleOrNull()
                                userRow?.get(Users.username)
                            }
                        }
                    }
                    if (username != null) {
                        call.respond(MeResponse(username))
                    } else {
                        call.respond(io.ktor.http.HttpStatusCode.Unauthorized, AuthResponse(false, "令牌无效或已过期"))
                    }
                }
            }

            // ===== 发帖（需要登录）=====
            post( path = "/posts") {
                val header = call.request.header("Authorization")
                val now = System.currentTimeMillis()
                val username = if (header == null) null else transaction {
                    val r = Tokens.selectAll().where { Tokens.token eq header }.singleOrNull()
                    if (r != null && r[Tokens.expiresAt] > now) r[Tokens.username] else null
                }
                if (username == null) {
                    call.respond(io.ktor.http.HttpStatusCode.Unauthorized, AuthResponse(false, "未登录或令牌过期"))
                } else {
                    val body = Gson().fromJson(call.receiveText(), PostRequest::class.java)
                    when {
                        body.content.isBlank() -> call.respond(AuthResponse(false, "内容不能为空"))
                        body.content.length > 500 -> call.respond(AuthResponse(false, "最多 500 字"))
                        else -> {
                            transaction {
                                Posts.insert {
                                    it[Posts.username] = username
                                    it[content] = body.content
                                    it[createdAt] = now
                                }
                            }
                            call.respond(AuthResponse(true, "发布成功"))
                        }
                    }
                }
            }

            // ===== 动态列表（公开，分页）=====
            get( path = "/posts") {
                val page = call.request.queryParameters["page"]?.toIntOrNull() ?: 0
                val size = (call.request.queryParameters["size"]?.toIntOrNull() ?: 20).coerceIn(1, 50)
                val list = transaction {
                    Posts.selectAll()
                        .orderBy(Posts.id, SortOrder.DESC)
                        .limit(size).offset(page * size.toLong())
                        .map {
                            PostItem(
                                id = it[Posts.id],
                                username = it[Posts.username],
                                content = it[Posts.content],
                                createdAt = it[Posts.createdAt]
                            )
                        }
                }
                val total = transaction { Posts.selectAll().count() }
                call.respond(PostPage(list, total))
            }
        }
    }.start(wait = true)
}
