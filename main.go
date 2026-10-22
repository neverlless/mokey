// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/neverlless/mokey/v2/cmd"
	_ "github.com/neverlless/mokey/v2/cmd/serve"
)

func main() {
	cmd.Execute()
}
