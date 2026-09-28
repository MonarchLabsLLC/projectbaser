// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.
import React from 'react'
import {FormattedMessage} from 'react-intl'

import './legacySunsetBanner.scss'

export const NEW_PROJECTBASER_URL = 'https://go.pipeleads.ai/pm/boards'

const LegacySunsetBanner = () => (
    <div
        className='LegacySunsetBanner'
        role='status'
    >
        <span className='LegacySunsetBanner__text'>
            <strong>
                <FormattedMessage
                    id='LegacySunsetBanner.title'
                    defaultMessage='This is the legacy version of ProjectBaser.'
                />
            </strong>
            {' '}
            <FormattedMessage
                id='LegacySunsetBanner.body'
                defaultMessage='We recommend moving your data to the new ProjectBaser. This legacy app will be sunset within the next 90 days.'
            />
        </span>
        <a
            className='LegacySunsetBanner__link'
            href={NEW_PROJECTBASER_URL}
            target='_blank'
            rel='noopener noreferrer'
        >
            <FormattedMessage
                id='LegacySunsetBanner.cta'
                defaultMessage='Go to the new ProjectBaser'
            />
        </a>
    </div>
)

export default React.memo(LegacySunsetBanner)
