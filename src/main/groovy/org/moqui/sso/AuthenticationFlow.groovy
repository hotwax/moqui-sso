package org.moqui.sso

import org.moqui.context.ExecutionContext
import org.moqui.impl.context.UserFacadeImpl
import org.pac4j.core.authorization.authorizer.DefaultAuthorizers
import org.pac4j.core.client.Client
import org.pac4j.core.config.Config
import org.pac4j.core.engine.DefaultCallbackLogic
import org.pac4j.core.engine.DefaultLogoutLogic
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.profile.factory.ProfileManagerFactory
import org.pac4j.core.profile.UserProfile
import org.pac4j.jee.context.JEEContext
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.JEEFrameworkParameters
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.jee.context.session.JEESessionStoreFactory
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter
import org.pac4j.saml.state.SAML2StateGenerator

class AuthenticationFlow {

    /**
     * Performs a login operation.
     */
    static void loginUser(ExecutionContext ec) {

        // parameters
        String authFlowId = ec.context.get("authFlowId") as String
        String returnTo = ec.context.get("returnTo") as String
        String baseUrl = ec.web.getWebappRootUrl(true, false)
        String callbackUrl = baseUrl + "/sso/callback"

        // init fields required for logic
        JEEContext context = new JEEContext(ec.web.request, ec.web.response)
        JEESessionStore sessionStore = new JEESessionStore()   // pac4j 6.3.1: the INSTANCE singleton was removed from JEESessionStore
        MoquiSecurityGrantedAccessAdapter securityGrantedAccessAdapter = new MoquiSecurityGrantedAccessAdapter(ec)
        JEEHttpActionAdapter actionAdapter = JEEHttpActionAdapter.INSTANCE

        // store return URL
        if (returnTo) {
            ec.web.sessionAttributes.put("moquiAuthFlowReturnTo", returnTo)
            sessionStore.set(context, SAML2StateGenerator.SAML_RELAY_STATE_ATTRIBUTE, returnTo)
        }

        // init config (pac4j 6: JEE adapters travel on the Config, request/response via FrameworkParameters)
        Client client = new AuthenticationClientFactory(ec).build(authFlowId)
        Config config = new Config(callbackUrl, client)
        config.setWebContextFactory(JEEContextFactory.INSTANCE)
        config.setSessionStoreFactory(JEESessionStoreFactory.INSTANCE)
        config.setHttpActionAdapter(actionAdapter)
        config.setProfileManagerFactory(ProfileManagerFactory.DEFAULT)

        // perform logic
        try {
            DefaultSecurityLogic.INSTANCE.perform(
                    config,
                    securityGrantedAccessAdapter,
                    authFlowId,
                    DefaultAuthorizers.IS_AUTHENTICATED,
                    null,
                    new JEEFrameworkParameters(ec.web.request, ec.web.response)
            )
        } catch (RuntimeException e) {
            ec.logger.error("An error occurred while performing login action", e)
            ec.web.response.sendRedirect(baseUrl + "/Login")
        }
    }

    /**
     * Handles the login callback.
     */
    static void handleCallback(ExecutionContext ec) {

        // parameters
        String baseUrl = ec.web.getWebappRootUrl(true, false)

        // init fields required for logic
        JEEContext context = new JEEContext(ec.web.request, ec.web.response)
        JEESessionStore sessionStore = new JEESessionStore()   // pac4j 6.3.1: the INSTANCE singleton was removed from JEESessionStore
        MoquiSecurityGrantedAccessAdapter securityGrantedAccessAdapter = new MoquiSecurityGrantedAccessAdapter(ec)
        JEEHttpActionAdapter actionAdapter = JEEHttpActionAdapter.INSTANCE

        // init config (pac4j 6: JEE adapters travel on the Config, request/response via FrameworkParameters)
        Config config = new Config(ec.web.getWebappRootUrl(true, false) + "/sso/callback", new org.moqui.sso.AuthenticationClientFactory(ec).buildAll())
        config.setWebContextFactory(JEEContextFactory.INSTANCE)
        config.setSessionStoreFactory(JEESessionStoreFactory.INSTANCE)
        config.setHttpActionAdapter(actionAdapter)
        config.setProfileManagerFactory(ProfileManagerFactory.DEFAULT)

        // retrieve return URL from "RelayState" parameter (SAML only), or from session attribute
        String redirectTo = context.getRequestParameter("RelayState").orElse(ec.web.sessionAttributes.moquiAuthFlowReturnTo as String)

        // perform logic
        try {
            DefaultCallbackLogic.INSTANCE.perform(
                    config,
                    null,
                    false,
                    null,
                    new JEEFrameworkParameters(ec.web.request, ec.web.response)
            )

            // handle incoming profiles
            ProfileManager profileManager = new ProfileManager(context, sessionStore)
            securityGrantedAccessAdapter.adapt(context, sessionStore, profileManager.getProfiles())

            // login user
            Optional<UserProfile> optionalProfile = profileManager.getProfile()
            if (optionalProfile.isPresent()) {
                UserProfile profile = optionalProfile.get()
                ((UserFacadeImpl) ec.user).internalLoginUser(profile.username)
                ec.web.sessionAttributes.put("moquiAuthFlowExternalLogout", true)
                ec.web.sessionAttributes.put("moquiAuthFlowReturnTo", redirectTo)
            }
        } catch (RuntimeException e) {
            ec.logger.error("An error occurred while handling callback", e)
            ec.web.response.sendRedirect(baseUrl + "/Login")
        }
    }

    /**
     * Performs a logout operation.
     */
    static void logoutUser(ExecutionContext ec) {

        // parameters
        String returnTo = ec.context.get("returnTo") as String
        String baseUrl = ec.web.getWebappRootUrl(true, false)
        String callbackUrl = returnTo ?: baseUrl + "/Login"

        // init fields required for logic
        JEEContext context = new JEEContext(ec.web.request, ec.web.response)
        JEESessionStore sessionStore = new JEESessionStore()   // pac4j 6.3.1: the INSTANCE singleton was removed from JEESessionStore
        JEEHttpActionAdapter actionAdapter = JEEHttpActionAdapter.INSTANCE

        // init config (pac4j 6: JEE adapters travel on the Config, request/response via FrameworkParameters)
        Config config = new Config(baseUrl + "/sso/callback", new AuthenticationClientFactory(ec).buildAll())
        config.setWebContextFactory(JEEContextFactory.INSTANCE)
        config.setSessionStoreFactory(JEESessionStoreFactory.INSTANCE)
        config.setHttpActionAdapter(actionAdapter)
        config.setProfileManagerFactory(ProfileManagerFactory.DEFAULT)

        // perform logic
        try {
            DefaultLogoutLogic.INSTANCE.perform(
                    config,
                    callbackUrl,
                    null,
                    false,
                    false,
                    true,
                    new JEEFrameworkParameters(ec.web.request, ec.web.response)
            )

            // logout user
            ec.user.logoutUser()
        } catch (RuntimeException e) {
            ec.logger.error("An error occurred while performing logout action", e)
            ec.web.response.sendRedirect(returnTo ?: baseUrl + "/Login")
        }
    }
}
