// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React, {useState} from 'react'
import {useIntl} from 'react-intl'
import {useHistory} from 'react-router-dom'

import {Constants} from '../../constants'
import octoClient from '../../octoClient'
import {IUser} from '../../user'
import FocalboardLogoIcon from '../../widgets/icons/focalboard_logo'
import Menu from '../../widgets/menu'
import MenuWrapper from '../../widgets/menuWrapper'
import {getMe, setMe} from '../../store/users'
import {useAppSelector, useAppDispatch} from '../../store/hooks'

import ModalWrapper from '../modalWrapper'

import {IAppWindow} from '../../types'

import {keycloakLogout} from '../../services/keycloak'

import RegistrationLink from './registrationLink'

import './sidebarUserMenu.scss'

declare let window: IAppWindow

const SidebarUserMenu = () => {
    const dispatch = useAppDispatch()
    const history = useHistory()
    const [showRegistrationLinkDialog, setShowRegistrationLinkDialog] = useState(false)
    const user = useAppSelector<IUser|null>(getMe)
    const intl = useIntl()

    const handleLogout = () => {
        // Clear Redux state
        dispatch(setMe(null))

        // Clear local storage session
        localStorage.removeItem('focalboardSessionId')

        // Redirect to ScalePlus logout
        keycloakLogout()
    }

    return (
        <div className='SidebarUserMenu'>
            <ModalWrapper>
                <MenuWrapper>
                    <div className='logo'>
                        <div className='logo-title'>
                            <FocalboardLogoIcon/>
                            <span>{'ProjectBaser'}</span>
                        </div>
                    </div>
                    <Menu>
                        {user && user.username !== 'single-user' && <>
                            <Menu.Label><b>{user.username}</b></Menu.Label>
                            <Menu.Text
                                id='logout'
                                name={intl.formatMessage({id: 'Sidebar.logout', defaultMessage: 'Log out'})}
                                onClick={handleLogout}
                            />
                            <Menu.Text
                                id='invite'
                                name={intl.formatMessage({id: 'Sidebar.invite-users', defaultMessage: 'Invite users'})}
                                onClick={async () => {
                                    setShowRegistrationLinkDialog(true)
                                }}
                            />

                            <Menu.Separator/>
                        </>}

                        <Menu.Text
                            id='about'
                            name={intl.formatMessage({id: 'Sidebar.about', defaultMessage: 'About ProjectBaser'})}
                            onClick={async () => {
                                window.open('/about', '_blank')
                            }}
                        />
                    </Menu>
                </MenuWrapper>

                {showRegistrationLinkDialog &&
                    <RegistrationLink
                        onClose={() => {
                            setShowRegistrationLinkDialog(false)
                        }}
                    />
                }
            </ModalWrapper>
        </div>
    )
}

export default React.memo(SidebarUserMenu)
