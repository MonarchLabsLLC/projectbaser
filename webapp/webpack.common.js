// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.
const path = require('path');
const webpack = require('webpack');

const tsTransformer = require('@formatjs/ts-transformer');
const CopyPlugin = require('copy-webpack-plugin');
var HtmlWebpackPlugin = require('html-webpack-plugin');

const outpath = path.resolve(__dirname, 'pack');

// Keycloak configuration from environment variables
const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL || 'https://auth.groovetech.io/auth';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'gd-apis-live';
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'app-projectbaser';

function makeCommonConfig() {
    const commonConfig = {
        target: 'web',
        mode: 'development',
        node: {
            __dirname: false,
            __filename: false,
        },
        module: {
            rules: [
                {
                    test: /\.m?js/,
                    resolve: {
                        fullySpecified: false,
                    },
                },
                {
                    test: /\.tsx?$/,
                    use: {
                        loader: 'ts-loader',
                        options: {
                            getCustomTransformers: {
                                before: [
                                    tsTransformer.transform({
                                        overrideIdFn: '[sha512:contenthash:base64:6]',
                                        ast: true,
                                    }),
                                ],
                            },
                        },
                    },
                    exclude: [/node_modules/],

                },
                {
                    test: /\.html$/,
                    type: 'asset/resource',
                },
                {
                    test: /\.s[ac]ss$/i,
                    use: [
                        'style-loader',
                        'css-loader',
                        'sass-loader',
                    ],
                },
                {
                    test: /\.css$/i,
                    use: [
                        'style-loader',
                        'css-loader',
                    ],
                },
                {
                    test: /\.(tsx?|js|jsx|mjs|html)$/,
                    use: [
                    ],
                    exclude: [/node_modules/],
                },
                {
                    test: /\.(eot|tiff|svg|woff2|woff|ttf|png|jpg|jpeg|gif)$/,
                    type: 'asset/resource',
                    generator: {
                        filename: 'static/[name][ext]',
                    },
                },
            ],
        },
        resolve: {
            modules: [
                'node_modules',
                path.resolve(__dirname),
            ],
            fullySpecified: false,
            extensions: ['.js', '.jsx', '.ts', '.tsx'],
        },
        plugins: [
            new webpack.DefinePlugin({
                'window.KEYCLOAK_BASE_URL': JSON.stringify(KEYCLOAK_BASE_URL),
                'window.KEYCLOAK_REALM': JSON.stringify(KEYCLOAK_REALM),
                'window.KEYCLOAK_CLIENT_ID': JSON.stringify(KEYCLOAK_CLIENT_ID),
            }),
            new CopyPlugin({
                patterns: [
                    {from: path.resolve(__dirname, 'static'), to: 'static'},
                ],
            }),
            new HtmlWebpackPlugin({
                inject: true,
                title: 'ProjectBaser',
                chunks: ['main'],
                template: 'html-templates/page.ejs',
                filename: 'index.html',
                publicPath: '{{.BaseURL}}/',
                hash: false,
            }),
        ],
        entry: ['./src/main.tsx', './src/userSettings.ts'],
        output: {
            library: 'ProjectBaser',
            filename: 'static/[name].[contenthash:8].js',
            path: outpath,
        },
    };

    return commonConfig;
}

module.exports = makeCommonConfig;
