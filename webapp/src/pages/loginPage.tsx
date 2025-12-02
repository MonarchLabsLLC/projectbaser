// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.
import React, {useEffect} from 'react'
import {Redirect} from 'react-router-dom'

import {useAppSelector} from '../store/hooks'
import {getLoggedIn} from '../store/users'

import {keycloakLogin, isKeycloakAuthenticated} from '../services/keycloak'

import './loginPage.scss'

const LoginPage = () => {
    const loggedIn = useAppSelector<boolean|null>(getLoggedIn)

    useEffect(() => {
        // If not logged in and not already authenticated with Keycloak, redirect to Keycloak login
        if (loggedIn === false && !isKeycloakAuthenticated()) {
            keycloakLogin()
        }
    }, [loggedIn])

    // If already logged in, redirect to home
    if (loggedIn) {
        return <Redirect to={'/'}/>
    }

    // Show loading state while redirecting to Keycloak
    return (
        <div className='LoginPage'>
            <div className='login-container'>
                <div className='login-header'>
                    <svg className='login-logo' viewBox='0 0 24 24' fill='none' stroke='currentColor' strokeWidth='2' strokeLinecap='round' strokeLinejoin='round'>
                        <polygon points='12 2 2 7 12 12 22 7 12 2'></polygon>
                        <polyline points='2 17 12 22 22 17'></polyline>
                        <polyline points='2 12 12 17 22 12'></polyline>
                    </svg>
                    <h1>ProjectBaser</h1>
                </div>
                <div className='loading-section'>
                    <div className='loading-spinner' style={{
                        width: '32px',
                        height: '32px',
                        border: '3px solid rgba(255, 255, 255, 0.2)',
                        borderTopColor: 'rgba(255, 255, 255, 0.8)',
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
                    <p style={{
                        color: 'rgba(255, 255, 255, 0.8)',
                        textAlign: 'center',
                        margin: 0,
                    }}>
                        Redirecting to login...
                    </p>
                </div>
            </div>
        </div>
    )
}

export default React.memo(LoginPage)
