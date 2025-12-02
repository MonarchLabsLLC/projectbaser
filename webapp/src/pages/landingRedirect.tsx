// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.
import React, {useEffect} from 'react'
import {useHistory} from 'react-router-dom'

import {getLoggedIn} from '../store/users'
import {useAppSelector} from '../store/hooks'

const LandingRedirect = (): JSX.Element | null => {
    const loggedIn = useAppSelector<boolean|null>(getLoggedIn)
    const history = useHistory()

    useEffect(() => {
        if (loggedIn === true) {
            // User is logged in, redirect to their team dashboard
            const teamId = localStorage.getItem('focalboardTeamId') || '0'
            history.replace(`/team/${teamId}`)
        } else if (loggedIn === false) {
            // User is not logged in, show landing page
            window.location.href = '/static/landing/index.html'
        }
        // If loggedIn is null, we're still checking, so wait
    }, [loggedIn, history])

    return null
}

export default LandingRedirect
