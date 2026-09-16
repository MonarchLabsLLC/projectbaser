// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// Presentation and transport helpers for the server-authorized workspace
// adapter. The short-lived launch code remains in the URL only; authorization
// context and bearer tokens never enter browser storage.
const codeParam = 'scale_workspace_code'
let featureEnabled = false

export const setScaleWorkspaceFeatureEnabled = (enabled: boolean): void => {
    featureEnabled = enabled
}
export const isScaleWorkspaceFeatureEnabled = (): boolean => featureEnabled

export const getPendingScaleWorkspaceCode = (): string => {
    try {
        const code = new URLSearchParams(window.location.search).get(codeParam) || ''
        return code.length > 0 && code.length <= 256 && (/^[\x21-\x7e]+$/).test(code) ? code : ''
    } catch {
        return ''
    }
}

export const removeScaleWorkspaceCodeFromURL = (): void => {
    try {
        const url = new URL(window.location.href)
        if (url.searchParams.has(codeParam)) {
            url.searchParams.delete(codeParam)
            window.history.replaceState({}, document.title, url.pathname + url.search + url.hash)
        }
    } catch {
        // Best effort only; the server still validates and consumes the code once.
    }
}

export type ScaleWorkspaceExchangeResult = {
    teamId: string
    returnPath: string
}
