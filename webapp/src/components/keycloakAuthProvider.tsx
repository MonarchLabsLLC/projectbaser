// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React, {createContext, useContext, useEffect, useState, useCallback} from 'react'

import {
    initKeycloak,
    keycloakLogin,
    keycloakLogout,
    isKeycloakAuthenticated,
    getKeycloakToken,
    hasKeycloakRole,
    getKeycloakUserInfo,
    refreshKeycloakToken,
} from '../services/keycloak'
import client from '../octoClient'
import {useAppDispatch} from '../store/hooks'
import {setMe} from '../store/users'
import {IUser} from '../user'

// Required role for accessing this application
const REQUIRED_ROLE = 'app_pipeleads'

// Access denied redirect URL
const ACCESS_DENIED_URL = 'https://app.scaleplus.gg/dashboard?error=access_denied&app=pipeleads'

interface KeycloakAuthContextType {
    isAuthenticated: boolean
    isInitialized: boolean
    isLoading: boolean
    user: IUser | null
    login: () => void
    logout: () => void
    getToken: () => string | undefined
    hasRole: (role: string) => boolean
}

const KeycloakAuthContext = createContext<KeycloakAuthContextType | undefined>(undefined)

interface KeycloakAuthProviderProps {
    children: React.ReactNode
}

export const KeycloakAuthProvider: React.FC<KeycloakAuthProviderProps> = ({children}) => {
    const [isAuthenticated, setIsAuthenticated] = useState(false)
    const [isInitialized, setIsInitialized] = useState(false)
    const [isLoading, setIsLoading] = useState(true)
    const [user, setUser] = useState<IUser | null>(null)
    const dispatch = useAppDispatch()

    useEffect(() => {
        let isMounted = true

        const handleBackendLogin = async (token: string): Promise<IUser | null> => {
            try {
                const response = await client.keycloakLogin(token)
                if (response) {
                    // Store the session token and team ID
                    localStorage.setItem('focalboardSessionId', response.token)
                    if (response.teamId) {
                        localStorage.setItem('focalboardTeamId', response.teamId)
                    }

                    // Update Redux store with user data
                    dispatch(setMe(response.user))

                    return response.user
                }
                return null
            } catch (error) {
                console.error('Backend login failed:', error)
                return null
            }
        }

        const initAuth = async () => {
            if (!isMounted) return
            
            setIsLoading(true)

            try {
                // Initialize Keycloak
                const authenticated = await initKeycloak()

                if (!isMounted) return

                if (authenticated) {
                    // Check for required role
                    if (!hasKeycloakRole(REQUIRED_ROLE)) {
                        console.warn('User does not have required role:', REQUIRED_ROLE)
                        // Redirect to access denied page
                        window.location.href = ACCESS_DENIED_URL
                        return
                    }

                    // Get token and authenticate with backend
                    const token = getKeycloakToken()
                    if (token) {
                        const loggedInUser = await handleBackendLogin(token)
                        if (!isMounted) return
                        
                        if (loggedInUser) {
                            setUser(loggedInUser)
                            setIsAuthenticated(true)
                        } else {
                            // Backend login failed
                            console.error('Backend authentication failed')
                            // Don't redirect to login again - just show error state
                        }
                    }
                }

                if (isMounted) {
                    setIsInitialized(true)
                }
            } catch (error) {
                console.error('Authentication initialization failed:', error)
                if (isMounted) {
                    setIsInitialized(true)
                }
            } finally {
                if (isMounted) {
                    setIsLoading(false)
                }
            }
        }

        initAuth()

        return () => {
            isMounted = false
        }
    }, [dispatch])

    const login = useCallback(() => {
        keycloakLogin()
    }, [])

    const logout = useCallback(() => {
        // Clear user state
        setUser(null)
        setIsAuthenticated(false)
        dispatch(setMe(null))

        // Perform Keycloak logout (redirects to ScalePlus)
        keycloakLogout()
    }, [dispatch])

    const getToken = useCallback(() => {
        return getKeycloakToken()
    }, [])

    const hasRole = useCallback((role: string) => {
        return hasKeycloakRole(role)
    }, [])

    const contextValue: KeycloakAuthContextType = {
        isAuthenticated,
        isInitialized,
        isLoading,
        user,
        login,
        logout,
        getToken,
        hasRole,
    }

    // Show loading state while initializing
    if (!isInitialized) {
        return (
            <div className="keycloak-loading" style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: '100vh',
                backgroundColor: '#1e1e2e',
                color: '#cdd6f4',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            }}>
                <div style={{textAlign: 'center'}}>
                    <div style={{
                        width: '40px',
                        height: '40px',
                        border: '3px solid #45475a',
                        borderTopColor: '#89b4fa',
                        borderRadius: '50%',
                        animation: 'spin 1s linear infinite',
                        margin: '0 auto 16px',
                    }} />
                    <style>
                        {`
                            @keyframes spin {
                                to { transform: rotate(360deg); }
                            }
                        `}
                    </style>
                    <p>Authenticating...</p>
                </div>
            </div>
        )
    }

    return (
        <KeycloakAuthContext.Provider value={contextValue}>
            {children}
        </KeycloakAuthContext.Provider>
    )
}

/**
 * Hook to access Keycloak authentication context
 */
export const useKeycloakAuth = (): KeycloakAuthContextType => {
    const context = useContext(KeycloakAuthContext)
    if (!context) {
        throw new Error('useKeycloakAuth must be used within a KeycloakAuthProvider')
    }
    return context
}

/**
 * HOC to require authentication for a component
 */
export const withKeycloakAuth = <P extends object>(
    WrappedComponent: React.ComponentType<P>
): React.FC<P> => {
    const WithAuth: React.FC<P> = (props) => {
        const {isAuthenticated, isInitialized, login} = useKeycloakAuth()

        useEffect(() => {
            if (isInitialized && !isAuthenticated) {
                login()
            }
        }, [isInitialized, isAuthenticated, login])

        if (!isInitialized || !isAuthenticated) {
            return null
        }

        return <WrappedComponent {...props} />
    }

    WithAuth.displayName = `withKeycloakAuth(${WrappedComponent.displayName || WrappedComponent.name || 'Component'})`

    return WithAuth
}

export default KeycloakAuthProvider

