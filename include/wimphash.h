/*
* 	wimphash - windows import hash tool
*
*	libwimp.h
*
* 	Author: Leandro Fróes
*
*	Copyright (C) 2019 Leandro Fróes
*
*	This program is free software: you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation, either version 3 of the License, or
*	(at your option) any later version.
*	This program is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*	You should have received a copy of the GNU General Public License
*	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>

#define MAX_DLL_NAME 512
#define MAX_FUNCTION_NAME 256

#define MD5LEN 16

void error(const char *msg);
void usage();
void cat(char *dest, char *dll, char *funcName);
void getHash(char *impStr, DWORD len);
void getFunctions(PIMAGE_THUNK_DATA impTable, LPVOID baseAddr, char *impStr, char *dll);
bool isPE(PIMAGE_DOS_HEADER dos, PIMAGE_NT_HEADERS pe);
void init(LPVOID baseAddr);
void createMap(LPCSTR filePath);
void clean(LPVOID baseAddr, HANDLE mapH, HANDLE fH);
