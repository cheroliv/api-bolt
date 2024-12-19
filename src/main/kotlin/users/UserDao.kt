@file:Suppress("MemberVisibilityCanBePrivate")

package users

import app.database.EntityModel
import app.utils.Constants.ROLE_USER
import arrow.core.Either
import arrow.core.left
import arrow.core.right
import jakarta.validation.ConstraintViolation
import jakarta.validation.Validator
import org.springframework.beans.factory.getBean
import org.springframework.context.ApplicationContext
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate
import org.springframework.r2dbc.core.*
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.transaction.reactive.TransactionalOperator
import org.springframework.transaction.reactive.executeAndAwait
import users.User.Attributes.EMAILORLOGIN
import users.User.Attributes.EMAIL_ATTR
import users.User.Attributes.ID_ATTR
import users.User.Attributes.LANG_KEY_ATTR
import users.User.Attributes.LOGIN_ATTR
import users.User.Attributes.PASSWORD_ATTR
import users.User.Attributes.VERSION_ATTR
import users.User.Fields.EMAIL_FIELD
import users.User.Fields.ID_FIELD
import users.User.Fields.LANG_KEY_FIELD
import users.User.Fields.LOGIN_FIELD
import users.User.Fields.PASSWORD_FIELD
import users.User.Fields.VERSION_FIELD
import users.User.Members.ROLES_MEMBER
import users.User.Relations.COUNT
import users.User.Relations.DELETE_USER
import users.User.Relations.DELETE_USER_BY_ID
import users.User.Relations.EMAIL_AVAILABLE_COLUMN
import users.User.Relations.FIND_USER_BY_EMAIL
import users.User.Relations.FIND_USER_BY_ID
import users.User.Relations.FIND_USER_BY_LOGIN
import users.User.Relations.FIND_USER_BY_LOGIN_OR_EMAIL
import users.User.Relations.FIND_USER_WITH_AUTHS_BY_EMAILOGIN
import users.User.Relations.INSERT
import users.User.Relations.LOGIN_AND_EMAIL_AVAILABLE_COLUMN
import users.User.Relations.LOGIN_AVAILABLE_COLUMN
import users.User.Relations.SELECT_SIGNUP_AVAILABILITY
import users.security.UserRoleDao.signup
import users.signup.Signup
import users.signup.UserActivation
import users.signup.UserActivation.Attributes.ACTIVATION_KEY_ATTR
import users.signup.UserActivation.Companion.USERACTIVATIONCLASS
import users.signup.UserActivationDao.save
import java.lang.Boolean.parseBoolean
import java.lang.Long.getLong
import java.util.*
import java.util.UUID.fromString


object UserDao {

    fun Pair<String, ApplicationContext>.isActivationKeySizeValid()
            : Set<ConstraintViolation<UserActivation>> = second
        .getBean<Validator>()
        .validateValue(USERACTIVATIONCLASS, ACTIVATION_KEY_ATTR, first)

    fun Pair<String, ApplicationContext>.isEmail(): Boolean = second
        .getBean<Validator>()
        .validateValue(User::class.java, EMAIL_ATTR, first)
        .isEmpty()

    fun Pair<String, ApplicationContext>.isLogin(): Boolean = second
        .getBean<Validator>()
        .validateValue(User::class.java, LOGIN_ATTR, first)
        .isEmpty()

    suspend fun ApplicationContext.countUsers(): Int = COUNT
        .trimIndent()
        .let(getBean<DatabaseClient>()::sql)
        .fetch()
        .awaitSingle()
        .values
        .first()
        .toString()
        .toInt()

    @Throws(EmptyResultDataAccessException::class)
    suspend fun Pair<User, ApplicationContext>.save(): Either<Throwable, UUID> = try {
        INSERT
            .trimIndent()
            .run(second.getBean<R2dbcEntityTemplate>().databaseClient::sql)
            .bind(LOGIN_ATTR, first.login)
            .bind(EMAIL_ATTR, first.email)
            .bind(PASSWORD_ATTR, first.password)
            .bind(LANG_KEY_ATTR, first.langKey)
            .bind(VERSION_ATTR, first.version)
            .fetch()
            .awaitOne()[ID_ATTR]
            .toString()
            .run(UUID::fromString)
            .right()
    } catch (e: Throwable) {
        e.left()
    }

    suspend fun ApplicationContext.deleteAllUsersOnly(): Unit = DELETE_USER
        .trimIndent()
        .let(getBean<DatabaseClient>()::sql)
        .await()

    suspend fun ApplicationContext.delete(id: UUID): Unit = DELETE_USER_BY_ID
        .trimIndent()
        .let(getBean<DatabaseClient>()::sql)
        .bind(ID_ATTR, id)
        .await()

    suspend inline fun <reified T : EntityModel<UUID>> ApplicationContext.findOne(
        emailOrLogin: String
    ): Either<Throwable, User> = when (T::class) {
        User::class -> try {
            FIND_USER_BY_LOGIN_OR_EMAIL
                .trimIndent()
                .run(getBean<DatabaseClient>()::sql)
                .bind(EMAIL_ATTR, emailOrLogin)
                .bind(LOGIN_ATTR, emailOrLogin)
                .fetch()
                .awaitSingle()
                .let {
                    User(
                        id = fromString(it[ID_FIELD].toString()),
                        email = if ((emailOrLogin to this).isEmail()) emailOrLogin
                        else it[EMAIL_FIELD].toString(),
                        login = if ((emailOrLogin to this).isLogin()) emailOrLogin
                        else it[LOGIN_FIELD].toString(),
                        password = it[PASSWORD_FIELD].toString(),
                        langKey = it[LANG_KEY_FIELD].toString(),
                        version = it[VERSION_FIELD].toString().run(::getLong),
                    )
                }.right()
        } catch (e: Throwable) {
            e.left()
        }

        else -> (T::class.simpleName)
            .run { "Unsupported type: $this" }
            .run(::IllegalArgumentException)
            .left()
    }

    suspend inline fun <reified T : EntityModel<UUID>> ApplicationContext.findOne(
        id: UUID
    ): Either<Throwable, User> = when (T::class) {
        User::class -> try {
            FIND_USER_BY_ID
                .trimIndent()
                .run(getBean<DatabaseClient>()::sql)
                .bind(EMAIL_ATTR, id)
                .bind(LOGIN_ATTR, id)
                .fetch()
                .awaitSingleOrNull()
                .let {
                    User(
                        id = it?.get(ID_FIELD)
                            .toString()
                            .run(UUID::fromString),
                        email = it?.get(EMAIL_FIELD).toString(),
                        login = it?.get(LOGIN_FIELD).toString(),
                        password = it?.get(PASSWORD_FIELD).toString(),
                        langKey = it?.get(LANG_KEY_FIELD).toString(),
                        version = getLong(it?.get(VERSION_FIELD).toString()),
                    )
                }.right()
        } catch (e: Throwable) {
            e.left()
        }

        else -> (T::class.simpleName)
            .run { "Unsupported type: $this" }
            .run(::IllegalArgumentException)
            .left()
    }


    suspend inline fun <reified T : EntityModel<UUID>> ApplicationContext.findOneWithAuths(emailOrLogin: String): Either<Throwable, User> =
        when (T::class) {
            User::class -> {
                try {
                    if (!((emailOrLogin to this).isEmail() || (emailOrLogin to this).isLogin()))
                        "not a valid login or not a valid email"
                            .run(::Exception)
                            .left()

                    FIND_USER_WITH_AUTHS_BY_EMAILOGIN
                        .trimIndent()
                        .run(getBean<DatabaseClient>()::sql)
                        .bind(EMAILORLOGIN, emailOrLogin)
                        .fetch()
                        .awaitSingleOrNull()
                        .run {
                            when {
                                this == null -> Exception("not able to retrieve user id and roles").left()
                                else -> User(
                                    id = fromString(get(ID_FIELD).toString()),
                                    email = get(EMAIL_FIELD).toString(),
                                    login = get(LOGIN_FIELD).toString(),
                                    roles = get(ROLES_MEMBER)
                                        .toString()
                                        .split(",")
                                        .map { users.security.Role(it) }
                                        .toSet(),
                                    password = get(PASSWORD_FIELD).toString(),
                                    langKey = get(LANG_KEY_FIELD).toString(),
                                    version = get(VERSION_FIELD).toString().toLong(),
                                ).right()
                            }
                        }
                } catch (e: Throwable) {
                    e.left()
                }
            }

            else -> (T::class.simpleName)
                .run { "Unsupported type: $this" }
                .run(::IllegalArgumentException)
                .left()
        }

    suspend inline fun <reified T : EntityModel<UUID>> ApplicationContext.findOneByLogin(login: String): Either<Throwable, UUID> =
        when (T::class) {
            User::class -> {
                try {
                    FIND_USER_BY_LOGIN
                        .trimIndent()
                        .run(getBean<DatabaseClient>()::sql)
                        .bind(LOGIN_ATTR, login)
                        .fetch()
                        .awaitOne()
                        .let { fromString(it[ID_FIELD].toString()) }.right()
                } catch (e: Throwable) {
                    e.left()
                }
            }

            else -> IllegalArgumentException("Unsupported type: ${T::class.simpleName}").left()
        }


    suspend inline fun <reified T : EntityModel<UUID>> ApplicationContext.findOneByEmail(email: String): Either<Throwable, UUID> =
        when (T::class) {
            User::class -> {
                try {
                    FIND_USER_BY_EMAIL
                        .trimIndent()
                        .run(getBean<DatabaseClient>()::sql)
                        .bind(EMAIL_ATTR, email)
                        .fetch()
                        .awaitOne()
                        .let { fromString(it[ID_ATTR].toString()) }
                        .right()
                } catch (e: Throwable) {
                    e.left()
                }
            }

            else -> IllegalArgumentException("Unsupported type: ${T::class.simpleName}").left()
        }

    @Throws(EmptyResultDataAccessException::class)
    suspend fun Pair<User, ApplicationContext>.signupDao(): Either<Throwable, Pair<UUID, String>> = try {
        second.getBean<TransactionalOperator>().executeAndAwait {
            (first to second).save()
        }
        second.findOneByEmail<User>(first.email).mapLeft {
            return Exception("Unable to find user by email").left()
        }.map {
            (users.security.UserRole(userId = it, role = ROLE_USER) to second).signup()
            val userActivation = UserActivation(id = it)
            (userActivation to second).save()
            return (it to userActivation.activationKey).right()
        }
    } catch (e: Throwable) {
        e.left()
    }

    fun ApplicationContext.signupToUser(signup: Signup): User = signup.apply {
        // Validation du mot de passe et de la confirmation
        require(password == repassword) { "Passwords do not match!" }
    }.run {
        // Création d'un utilisateur à partir des données de Signup
        User(
            login = login,
            password = getBean<PasswordEncoder>().encode(password),
            email = email,
        )
    }

    suspend fun Pair<Signup, ApplicationContext>.signupAvailability()
            : Either<Throwable, Triple<Boolean/*OK*/, Boolean/*email*/, Boolean/*login*/>> = try {
        SELECT_SIGNUP_AVAILABILITY
            .trimIndent()
            .run(second.getBean<R2dbcEntityTemplate>().databaseClient::sql)
            .bind(LOGIN_ATTR, first.login)
            .bind(EMAIL_ATTR, first.email)
            .fetch()
            .awaitSingle()
            .run {
                Triple(
                    parseBoolean(this[LOGIN_AND_EMAIL_AVAILABLE_COLUMN].toString()),
                    parseBoolean(this[EMAIL_AVAILABLE_COLUMN].toString()),
                    parseBoolean(this[LOGIN_AVAILABLE_COLUMN].toString())
                ).right()
            }
    } catch (e: Throwable) {
        e.left()
    }
}
