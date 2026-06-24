package main

import "embed"

//go:embed static/js/dist/*
var staticJS embed.FS
