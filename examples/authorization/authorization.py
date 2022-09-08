#!/usr/bin/env python3

# Copyright 2022 Gregor Krmelj
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
# to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
# Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json
import sys
from typing import TextIO


def main():
    try:
        ai = get_authorize_input(sys.stdin)
    except json.JSONDecodeError as exp:
        return fatal("json decode error:" + str(exp))

    valid, err = ai.valid()
    if not valid:
        fatal("authorization input invalid: " + err)

    out = user_authorization(ai)
    write_authorize_output(sys.stdout, out)
    sys.exit(0)


class AuthorizationInput:
    clientUUID: str = None
    ipIsIPv6: bool = None
    clientIP: str = None
    targetIP: str = None
    targetProtocol: str = None
    targetPortStart: int = None
    targetPortEnd: int = None

    def valid(self) -> (bool, str):
        fx = ["clientUUID", "ipIsIPv6", "clientIP", "targetIP", "targetProtocol", "targetPortStart", "targetPortEnd"]

        for f in fx:
            if self.__getattribute__(f) is None:
                return False, f + " is None"

        return True, ""


class AuthorizationOutput:
    duration: int = 0

    def is_authorized(self) -> bool:
        return self.duration > 0


def user_authorization(ai: AuthorizationInput) -> AuthorizationOutput:
    """
    Returns the user's authorized duration in seconds. To signal that the user is not authorized, return 0.
    """

    # Perform no validation, allow all requests for 3 minutes
    # You can customize this part as much as you like. E.g. using the AuthorizationInput you can check if the user
    # has permission for the requested port.
    out = AuthorizationOutput()
    out.duration = 3 * 60
    return out


def get_authorize_input(f: TextIO) -> AuthorizationInput:
    f_input = "".join(f.readlines())

    ai_raw = json.loads(f_input)
    ai = AuthorizationInput()

    ai.clientUUID = ai_raw.get("clientUUID")
    ai.ipIsIPv6 = ai_raw.get("ipIsIPv6")
    ai.clientIP = ai_raw.get("clientIP")
    ai.targetIP = ai_raw.get("targetIP")
    ai.targetProtocol = ai_raw.get("targetProtocol")
    ai.targetPortStart = ai_raw.get("targetPortStart")
    ai.targetPortEnd = ai_raw.get("targetPortEnd")

    return ai


def write_authorize_output(f: TextIO, out: AuthorizationOutput):
    f.write(json.dumps({"duration": out.duration}))
    f.flush()


def fatal(err: str):
    sys.stderr.write(err + "\n")
    sys.stderr.flush()
    sys.exit(1)


if __name__ == "__main__":
    main()
