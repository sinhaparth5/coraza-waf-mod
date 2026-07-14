package main

import "embed"

//go:embed static/js/dist/*
var staticJS embed.FS

//go:embed static/css/dist/*
var staticCSS embed.FS

//go:embed static/imgs/*
var staticImgs embed.FS
