package users.security

import arrow.core.Either
import arrow.core.left
import arrow.core.right
import kotlinx.coroutines.reactive.collect
import org.springframework.beans.factory.getBean
import org.springframework.context.ApplicationContext
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate
import org.springframework.r2dbc.core.DatabaseClient
import org.springframework.r2dbc.core.await
import org.springframework.r2dbc.core.awaitSingle
import users.User.Attributes.LOGIN_ATTR
import users.User.Relations.DELETE_USER_BY_ID
import users.security.UserRole.Attributes.ROLE_ATTR
import users.security.UserRole.Attributes.USER_ID_ATTR
import users.security.UserRole.Fields.ID_FIELD
import users.security.UserRole.Relations.COUNT
import users.security.UserRole.Relations.DELETE
import users.security.UserRole.Relations.DELETE_USER_AUTHORITIES_BY_LOGIN
import users.security.UserRole.Relations.DELETE_USER_AUTHORITIES_BY_USER_ID
import users.security.UserRole.Relations.INSERT
import java.util.*

object UserRoleDao {
    suspend fun Pair<UserRole, ApplicationContext>.signup(): Either<Throwable, Long> = try {
        INSERT.trimIndent()
            .run(second.getBean<R2dbcEntityTemplate>().databaseClient::sql)
            .bind(USER_ID_ATTR, first.userId)
            .bind(ROLE_ATTR, first.role)
            .fetch()
            .one()
            .collect { it[ID_FIELD] }
            .toString()
            .toLong()
            .right()
    } catch (e: Exception) {
        e.left()
    }

    suspend fun ApplicationContext.countUserAuthority(): Int = COUNT
        .trimIndent()
        .let(getBean<DatabaseClient>()::sql)
        .fetch()
        .awaitSingle()
        .values
        .first()
        .toString()
        .toInt()

    suspend fun ApplicationContext.deleteAllUserAuthorities(): Unit = DELETE
        .trimIndent()
        .let(getBean<DatabaseClient>()::sql)
        .await()

    suspend fun ApplicationContext.deleteAllUserAuthorityByUserId(id: UUID) = DELETE_USER_AUTHORITIES_BY_USER_ID
        .let(getBean<DatabaseClient>()::sql)
        .bind(USER_ID_ATTR, id)
        .await()

    suspend fun ApplicationContext.deleteUserByIdWithAuthorities_(id: UUID) =
        getBean<DatabaseClient>().run {
            DELETE_USER_AUTHORITIES_BY_USER_ID
                .trimIndent()
                .let(::sql)
                .bind(USER_ID_ATTR, id)
                .await()
            DELETE_USER_BY_ID
                .trimIndent()
                .let(::sql)
                .bind(USER_ID_ATTR, id)
                .await()
        }

    val ApplicationContext.queryDeleteAllUserAuthorityByUserLogin
        get() = DELETE_USER_AUTHORITIES_BY_LOGIN
            .trimIndent()

    suspend fun ApplicationContext.deleteAllUserAuthorityByUserLogin(
        login: String
    ) = getBean<DatabaseClient>()
        .sql(queryDeleteAllUserAuthorityByUserLogin)
        .bind(LOGIN_ATTR, login)
        .await()
}
