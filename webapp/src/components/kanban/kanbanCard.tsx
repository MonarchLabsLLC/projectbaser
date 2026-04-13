// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.
import React, {useState, useCallback, useMemo} from 'react'
import {useIntl} from 'react-intl'
import {
    Circle, CheckSquare, Calendar, Clock, FileText, Image, Link, Tag, User, Users,
    Folder, File, Archive, Bookmark, Bell, Flag, Star, Heart, Target, TrendingUp,
    BarChart, PieChart, Activity, Briefcase, ShoppingCart, DollarSign, CreditCard,
    MapPin, Globe, Mail, Phone, MessageSquare, Send, Paperclip, Download, Upload,
    Settings, Wrench, Search, Filter, Eye, Lock, Unlock, Shield, AlertCircle,
    CheckCircle, XCircle, Info, HelpCircle, Home, Menu, ChevronRight, ChevronDown,
    Plus, Minus, X, Check, Edit, Trash, Copy, Clipboard, Share, ExternalLink,
    Zap, Code, Terminal, Box, Package, Layers, Grid, List, LayoutGrid, Columns,
    AlignLeft, AlignCenter, AlignRight, AlignJustify, Bold, Italic, Underline,
    Hash, AtSign, Percent, Smile, ThumbsUp, Award, Gift, Trophy, Lightbulb,
    Book, GraduationCap, Palette, Music, Video, Camera, Mic, Speaker,
    Wifi, Bluetooth, Battery, Cpu, HardDrive, Monitor, Printer, Smartphone,
    Tablet, Watch, Play, Pause, StopCircle, SkipForward, SkipBack,
    Volume, VolumeX, Sun, Moon, Cloud, CloudRain, Wind, Thermometer,
    // Additional icons from emoji mapping
    Hand, Move, CheckCircle2, AlertTriangle, Flame, Sparkles, CalendarDays,
    CalendarCheck, BarChart3, TrendingDown, Film, Sliders, Glasses,
    BookOpen, Laptop, Key, Trash2, Edit3, Banknote, PenTool, Microscope,
    Compass, Mountain, PartyPopper, Car, Inbox, Timer, Hourglass,
    FolderOpen, Rocket, Handshake, TestTube, Building, Plug, Frame, 
    CloudRainWind, Trees, Bug, Bird, Cat, Construction,
} from 'lucide-react'

import {getEmptyImage} from 'react-dnd-html5-backend'

import {Board, IPropertyTemplate} from '../../blocks/board'
import {Card} from '../../blocks/card'
import {useSortable} from '../../hooks/sortable'
import mutator from '../../mutator'
import TelemetryClient, {TelemetryActions, TelemetryCategory} from '../../telemetry/telemetryClient'
import {Utils} from '../../utils'
import MenuWrapper from '../../widgets/menuWrapper'
import Tooltip from '../../widgets/tooltip'
import PropertyValueElement from '../propertyValueElement'
import ConfirmationDialogBox, {ConfirmationDialogBoxProps} from '../confirmationDialogBox'
import './kanbanCard.scss'
import CardBadges from '../cardBadges'
import CardActionsMenu from '../cardActionsMenu/cardActionsMenu'
import CardActionsMenuIcon from '../cardActionsMenu/cardActionsMenuIcon'
import {convertEmojiToLucideIcon} from '../../lucideIconList'

const LucideIcons: Record<string, any> = {
    Circle, CheckSquare, Calendar, Clock, FileText, Image, Link, Tag, User, Users,
    Folder, File, Archive, Bookmark, Bell, Flag, Star, Heart, Target, TrendingUp,
    BarChart, PieChart, Activity, Briefcase, ShoppingCart, DollarSign, CreditCard,
    MapPin, Globe, Mail, Phone, MessageSquare, Send, Paperclip, Download, Upload,
    Settings, Wrench, Search, Filter, Eye, Lock, Unlock, Shield, AlertCircle,
    CheckCircle, XCircle, Info, HelpCircle, Home, Menu, ChevronRight, ChevronDown,
    Plus, Minus, X, Check, Edit, Trash, Copy, Clipboard, Share, ExternalLink,
    Zap, Code, Terminal, Box, Package, Layers, Grid, List, LayoutGrid, Columns,
    AlignLeft, AlignCenter, AlignRight, AlignJustify, Bold, Italic, Underline,
    Hash, AtSign, Percent, Smile, ThumbsUp, Award, Gift, Trophy, Lightbulb,
    Book, GraduationCap, Palette, Music, Video, Camera, Mic, Speaker,
    Wifi, Bluetooth, Battery, Cpu, HardDrive, Monitor, Printer, Smartphone,
    Tablet, Watch, Play, Pause, StopCircle, SkipForward, SkipBack,
    Volume, VolumeX, Sun, Moon, Cloud, CloudRain, Wind, Thermometer,
    // Additional icons from emoji mapping
    Hand, Move, CheckCircle2, AlertTriangle, Flame, Sparkles, CalendarDays,
    CalendarCheck, BarChart3, TrendingDown, Film, Sliders, Glasses,
    BookOpen, Laptop, Key, Trash2, Edit3, Banknote, PenTool, Microscope,
    Compass, Mountain, PartyPopper, Car, Inbox, Timer, Hourglass,
    FolderOpen, Rocket, Handshake, TestTube, Building, Plug, Frame,
    CloudRainWind, Trees, Bug, Bird, Cat, Construction,
}

export const OnboardingCardClassName = 'onboardingCard'

type Props = {
    card: Card
    board: Board
    visiblePropertyTemplates: IPropertyTemplate[]
    isSelected: boolean
    visibleBadges: boolean
    onClick?: (e: React.MouseEvent, card: Card) => void
    readonly: boolean
    onDrop: (srcCard: Card, dstCard: Card) => void
    showCard: (cardId?: string) => void
    isManualSort: boolean
}

const KanbanCard = (props: Props) => {
    const {card, board} = props
    const intl = useIntl()
    const canDrag = !props.readonly && props.isManualSort
    const [isDragging, isOver, cardRef, preview] = useSortable('card', card, canDrag, props.onDrop)
    const visiblePropertyTemplates = props.visiblePropertyTemplates || []
    let className = props.isSelected ? 'KanbanCard selected' : 'KanbanCard'
    if (props.isManualSort && isOver) {
        className += ' dragover'
    }

    // Disable react-dnd's default drag preview (prevent ghost card)
    React.useEffect(() => {
        if (preview) {
            preview(getEmptyImage(), { captureDraggingState: true })
        }
    }, [preview])

    // Track drag direction for dynamic tilt
    const dragStateRef = React.useRef<{
        lastX: number
        floatingElement: HTMLElement | null
    }>({ lastX: 0, floatingElement: null })

    // Create custom floating drag preview with directional tilt
    const handleDragStart = useCallback((e: React.DragEvent<HTMLDivElement>) => {
        if (!cardRef.current) return
        
        // Track initial position
        dragStateRef.current.lastX = e.clientX
        
        // Create an invisible 1x1 element to completely hide default drag ghost
        const invisibleDiv = document.createElement('div')
        invisibleDiv.style.cssText = 'position: absolute; width: 1px; height: 1px; opacity: 0;'
        document.body.appendChild(invisibleDiv)
        
        // Set the invisible element as drag image to hide browser's ghost
        if (e.dataTransfer) {
            e.dataTransfer.effectAllowed = 'move'
            e.dataTransfer.setDragImage(invisibleDiv, 0, 0)
        }
        
        // Remove invisible element after a moment
        setTimeout(() => {
            if (invisibleDiv.parentElement) {
                document.body.removeChild(invisibleDiv)
            }
        }, 0)
        
        // Create floating element that follows cursor
        const floatingCard = cardRef.current.cloneNode(true) as HTMLElement
        floatingCard.id = 'drag-preview-floating'
        floatingCard.className = floatingCard.className + ' floating-drag-preview'
        floatingCard.style.cssText = `
            position: fixed;
            left: ${e.clientX}px;
            top: ${e.clientY}px;
            transform: translate(-50%, -50%) scale(1.05);
            box-shadow: rgba(0, 0, 0, 0.25) 0 16px 32px, rgba(0, 0, 0, 0.15) 0 8px 16px;
            border-radius: 8px;
            opacity: 0.9;
            pointer-events: none;
            z-index: 10000;
            width: ${cardRef.current.offsetWidth}px;
        `
        
        document.body.appendChild(floatingCard)
        dragStateRef.current.floatingElement = floatingCard
    }, [])

    // Update position and tilt based on drag direction
    const handleDrag = useCallback((e: React.DragEvent<HTMLDivElement>) => {
        const floatingEl = dragStateRef.current.floatingElement
        if (!floatingEl) return
        
        // Skip if coordinates are 0 (happens at the end of drag)
        if (e.clientX === 0 && e.clientY === 0) return
        
        const deltaX = e.clientX - dragStateRef.current.lastX
        
        // Only update if we have valid movement
        if (Math.abs(deltaX) > 0) {
            dragStateRef.current.lastX = e.clientX
            
            // Determine rotation based on horizontal movement direction
            const rotation = deltaX > 0 ? 5 : -5
            
            // Update position and rotation
            floatingEl.style.left = `${e.clientX}px`
            floatingEl.style.top = `${e.clientY}px`
            floatingEl.style.transform = `translate(-50%, -50%) rotate(${rotation}deg) scale(1.05)`
        }
    }, [])

    // Clean up on drag end
    const handleDragEnd = useCallback(() => {
        const el = document.getElementById('drag-preview-floating')
        if (el && el.parentElement) {
            document.body.removeChild(el)
        }
        dragStateRef.current.floatingElement = null
    }, [])

    const [showConfirmationDialogBox, setShowConfirmationDialogBox] = useState<boolean>(false)
    const handleDeleteCard = useCallback(() => {
        if (!card) {
            Utils.assertFailure()
            return
        }
        TelemetryClient.trackEvent(TelemetryCategory, TelemetryActions.DeleteCard, {board: board.id, card: card.id})
        mutator.deleteBlock(card, 'delete card')
    }, [card, board.id])

    const confirmDialogProps: ConfirmationDialogBoxProps = useMemo(() => {
        return {
            heading: intl.formatMessage({id: 'CardDialog.delete-confirmation-dialog-heading', defaultMessage: 'Confirm card delete!'}),
            confirmButtonText: intl.formatMessage({id: 'CardDialog.delete-confirmation-dialog-button-text', defaultMessage: 'Delete'}),
            onConfirm: handleDeleteCard,
            onClose: () => {
                setShowConfirmationDialogBox(false)
            },
        }
    }, [handleDeleteCard])

    const handleDeleteButtonOnClick = useCallback(() => {
        // user trying to delete a card with blank name
        // but content present cannot be deleted without
        // confirmation dialog
        if (card?.title === '' && card?.fields?.contentOrder?.length === 0) {
            handleDeleteCard()
            return
        }
        setShowConfirmationDialogBox(true)
    }, [handleDeleteCard, card.title, card?.fields?.contentOrder?.length])

    const handleOnClick = useCallback((e: React.MouseEvent) => {
        if (props.onClick) {
            props.onClick(e, card)
        }
    }, [props.onClick, card])

    return (
        <>
            <div
                ref={props.readonly ? () => null : cardRef}
                className={`${className} ${isDragging ? 'is-dragging' : ''}`}
                draggable={canDrag}
                onDragStart={handleDragStart}
                onDrag={handleDrag}
                onDragEnd={handleDragEnd}
                style={{
                    opacity: isDragging ? 0 : 1,
                    cursor: isDragging ? 'grabbing' : 'pointer',
                }}
                onClick={handleOnClick}
            >
                {!props.readonly &&
                <MenuWrapper
                    className={'optionsMenu'}
                    stopPropagationOnToggle={true}
                >
                    <CardActionsMenuIcon/>
                    <CardActionsMenu
                        cardId={card!.id}
                        boardId={card!.boardId}
                        onClickDelete={handleDeleteButtonOnClick}
                        onClickDuplicate={() => {
                            TelemetryClient.trackEvent(TelemetryCategory, TelemetryActions.DuplicateCard, {board: board.id, card: card.id})
                            mutator.duplicateCard(
                                card.id,
                                board.id,
                                false,
                                'duplicate card',
                                false,
                                {},
                                async (newCardId) => {
                                    props.showCard(newCardId)
                                },
                                async () => {
                                    props.showCard(undefined)
                                },
                            )
                        }}
                    />
                </MenuWrapper>
                }

                <div className='octo-icontitle'>
                    { card.fields.icon ? (
                        <div className='octo-icon lucide-icon'>
                            {(() => {
                                const iconName = convertEmojiToLucideIcon(card.fields.icon)
                                const IconComponent = LucideIcons[iconName]
                                return IconComponent ? <IconComponent size={16} /> : <LucideIcons.Circle size={16} />
                            })()}
                        </div>
                    ) : undefined }
                    <div
                        key='__title'
                        className='octo-titletext'
                    >
                        {card.title || intl.formatMessage({id: 'KanbanCard.untitled', defaultMessage: 'Untitled'})}
                    </div>
                </div>
                {visiblePropertyTemplates.map((template) => (
                    <Tooltip
                        key={template.id}
                        title={template.name}
                    >
                        <PropertyValueElement
                            board={board}
                            readOnly={true}
                            card={card}
                            propertyTemplate={template}
                            showEmptyPlaceholder={false}
                        />
                    </Tooltip>
                ))}
                {props.visibleBadges && <CardBadges card={card}/>}
            </div>

            {showConfirmationDialogBox && <ConfirmationDialogBox dialogBox={confirmDialogProps}/>}

        </>
    )
}

export default React.memo(KanbanCard)
