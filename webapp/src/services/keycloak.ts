// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import Keycloak, {KeycloakConfig, KeycloakInitOptions} from 'keycloak-js'

// Keycloak configuration from environment variables or defaults
const keycloakConfig: KeycloakConfig = {
    url: (window as any).KEYCLOAK_BASE_URL || 'https://auth.groovetech.io/auth',
    realm: (window as any).KEYCLOAK_REALM || 'gd-apis-live',
    clientId: (window as any).KEYCLOAK_CLIENT_ID || 'app-projectbaser',
}

// Create Keycloak instance
const keycloak = new Keycloak(keycloakConfig)

// Initialize options for Keycloak
const initOptions: KeycloakInitOptions = {
    onLoad: 'check-sso',
    checkLoginIframe: true,
    silentCheckSsoRedirectUri: window.location.origin + '/static/silent-check-sso.html',
    pkceMethod: 'S256',
}

// Token refresh interval (in milliseconds) - refresh 60 seconds before expiry
const TOKEN_REFRESH_INTERVAL = 60000 // 1 minute

// Store for refresh interval ID
let refreshIntervalId: ReturnType<typeof setInterval> | null = null

/**
 * Initialize Keycloak and check SSO status
 * @returns Promise that resolves to true if authenticated, false otherwise
 */
export const initKeycloak = async (): Promise<boolean> => {
    try {
        const authenticated = await keycloak.init(initOptions)

        if (authenticated) {
            setupTokenRefresh()
        }

        return authenticated
    } catch (error) {
        console.error('Keycloak initialization failed:', error)
        return false
    }
}

/**
 * Login via Keycloak - redirects to Keycloak login page
 */
export const keycloakLogin = (): void => {
    keycloak.login({
        redirectUri: window.location.origin + '/',
    })
}

/**
 * Logout from Keycloak and clear local session
 * Redirects to ScalePlus logout page
 */
export const keycloakLogout = (): void => {
    // Clear refresh interval
    if (refreshIntervalId) {
        clearInterval(refreshIntervalId)
        refreshIntervalId = null
    }

    // Clear local storage
    localStorage.removeItem('focalboardSessionId')
    localStorage.removeItem('focalboardTeamId')

    // Redirect to ScalePlus logout (will redirect back to projectbaser after logout)
    const redirectUrl = encodeURIComponent(window.location.origin)
    window.location.href = `https://app.scaleplus.gg/logout?redirect=${redirectUrl}`
}

/**
 * Get the current access token
 * @returns The access token or undefined if not authenticated
 */
export const getKeycloakToken = (): string | undefined => {
    return keycloak.token
}

/**
 * Get the current refresh token
 * @returns The refresh token or undefined if not authenticated
 */
export const getKeycloakRefreshToken = (): string | undefined => {
    return keycloak.refreshToken
}

/**
 * Check if user is authenticated with Keycloak
 * @returns True if authenticated, false otherwise
 */
export const isKeycloakAuthenticated = (): boolean => {
    return keycloak.authenticated || false
}

/**
 * Get parsed token claims
 * @returns Parsed token object or undefined
 */
export const getKeycloakTokenParsed = (): Keycloak['tokenParsed'] => {
    return keycloak.tokenParsed
}

/**
 * Check if user has a specific role
 * @param role The role to check for
 * @returns True if user has the role, false otherwise
 */
export const hasKeycloakRole = (role: string): boolean => {
    // Check resource access (client-specific roles)
    if (keycloak.tokenParsed?.resource_access) {
        for (const clientId in keycloak.tokenParsed.resource_access) {
            const client = keycloak.tokenParsed.resource_access[clientId] as {roles?: string[]}
            if (client?.roles?.includes(role)) {
                return true
            }
        }
    }

    // Check realm roles
    if (keycloak.tokenParsed?.realm_access?.roles?.includes(role)) {
        return true
    }

    return false
}

/**
 * Refresh the access token
 * @param minValidity Minimum validity in seconds (default: 30)
 * @returns Promise that resolves to true if token was refreshed, false otherwise
 */
export const refreshKeycloakToken = async (minValidity = 30): Promise<boolean> => {
    try {
        const refreshed = await keycloak.updateToken(minValidity)
        if (refreshed) {
            console.debug('Keycloak token refreshed')
        }
        return refreshed
    } catch (error) {
        console.error('Failed to refresh Keycloak token:', error)
        // Token refresh failed, redirect to login
        keycloakLogin()
        return false
    }
}

/**
 * Setup automatic token refresh
 */
const setupTokenRefresh = (): void => {
    // Clear any existing interval
    if (refreshIntervalId) {
        clearInterval(refreshIntervalId)
    }

    // Set up periodic token refresh
    refreshIntervalId = setInterval(async () => {
        if (keycloak.authenticated) {
            await refreshKeycloakToken(70) // Refresh if token expires in less than 70 seconds
        }
    }, TOKEN_REFRESH_INTERVAL)

    // Also refresh on token expiry event
    keycloak.onTokenExpired = () => {
        console.debug('Keycloak token expired, refreshing...')
        refreshKeycloakToken(0)
    }
}

/**
 * Get user info from token
 */
export const getKeycloakUserInfo = (): {
    sub?: string
    email?: string
    name?: string
    given_name?: string
    family_name?: string
    preferred_username?: string
} => {
    const tokenParsed = keycloak.tokenParsed
    if (!tokenParsed) {
        return {}
    }

    return {
        sub: tokenParsed.sub,
        email: tokenParsed.email as string | undefined,
        name: tokenParsed.name as string | undefined,
        given_name: tokenParsed.given_name as string | undefined,
        family_name: tokenParsed.family_name as string | undefined,
        preferred_username: tokenParsed.preferred_username as string | undefined,
    }
}

/**
 * Get the Keycloak instance (for advanced usage)
 */
export const getKeycloakInstance = (): Keycloak => {
    return keycloak
}

export default keycloak

