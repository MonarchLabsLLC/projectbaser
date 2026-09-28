// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.
import React from 'react'
import {render, screen} from '@testing-library/react'
import '@testing-library/jest-dom'

import {wrapIntl} from '../testUtils'

import LegacySunsetBanner, {NEW_PROJECTBASER_URL} from './legacySunsetBanner'

describe('components/legacySunsetBanner', () => {
    test('announces the legacy sunset and links to the new ProjectBaser', () => {
        render(wrapIntl(<LegacySunsetBanner/>))

        expect(screen.getByText('This is the legacy version of ProjectBaser.')).toBeInTheDocument()
        expect(screen.getByText(/sunset within the next 90 days/)).toBeInTheDocument()

        const link = screen.getByRole('link', {name: 'Go to the new ProjectBaser'})
        expect(link).toHaveAttribute('href', NEW_PROJECTBASER_URL)
        expect(NEW_PROJECTBASER_URL).toBe('https://go.pipeleads.ai/pm/boards')
    })
})
