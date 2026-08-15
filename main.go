// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/neverlless/mokey/cmd"
	_ "github.com/neverlless/mokey/cmd/serve"
)

func main() {
	cmd.Execute()
}
