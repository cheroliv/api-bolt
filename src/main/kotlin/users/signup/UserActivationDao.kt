@file:Suppress("MemberVisibilityCanBePrivate")

package users.signup

import arrow.core.Either
import arrow.core.left
import arrow.core.right
import org.springframework.beans.factory.getBean
import org.springframework.context.ApplicationContext
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate
import org.springframework.r2dbc.core.*
import users.signup.UserActivation.Attributes.ACTIVATION_DATE_ATTR
import users.signup.UserActivation.Attributes.ACTIVATION_KEY_ATTR
import users.signup.UserActivation.Attributes.CREATED_DATE_ATTR
import users.signup.UserActivation.Attributes.ID_ATTR
import users.signup.UserActivation.Relations.COUNT
import users.signup.UserActivation.Relations.INSERT
import users.signup.UserActivation.Relations.UPDATE_ACTIVATION_BY_KEY
import java.util.*

object UserActivationDao {
    suspend fun ApplicationContext.countUserActivation() = COUNT
        .trimIndent()
        .let(getBean<DatabaseClient>()::sql)
        .fetch()
        .awaitSingle()
        .values
        .first()
        .toString()
        .toInt()

    @Throws(EmptyResultDataAccessException::class)
    suspend fun Pair<UserActivation, ApplicationContext>.save(): Either<Throwable, Long> = try {
        INSERT
            .trimIndent()
            .run(second.getBean<R2dbcEntityTemplate>().databaseClient::sql)
            .bind(ID_ATTR, first.id)
            .bind(ACTIVATION_KEY_ATTR, first.activationKey)
            .bind(CREATED_DATE_ATTR, first.createdDate)
            .bind(
                ACTIVATION_DATE_ATTR,
                @Suppress("NULLABILITY_MISMATCH_BASED_ON_JAVA_ANNOTATIONS")
                first.activationDate
            ).fetch()
            .awaitRowsUpdated()
            .right()
    } catch (e: Throwable) {
        e.left()
    }

    /**
     * If the Right value (the result of the database operation) is not equal to 1,
     * then either the key doesn't exist, or the user is already activated.
     */
    suspend fun ApplicationContext.activateDao(key: String): Either<Throwable, Long> = try {
        UPDATE_ACTIVATION_BY_KEY
            .trimIndent()
            .run(getBean<R2dbcEntityTemplate>().databaseClient::sql)
            .bind(ACTIVATION_KEY_ATTR, key)
            .fetch()
            .awaitRowsUpdated()
            .right()
    } catch (e: Throwable) {
        e.left()
    }
}
