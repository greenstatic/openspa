import io
import unittest
import authorization


class TestAuthorization(unittest.TestCase):
    def test_user_authorization(self):
        out = authorization.user_authorization(authorization.AuthorizationInput())
        self.assertIsInstance(out, authorization.AuthorizationOutput)
        self.assertEqual(out.duration, 180)

    def test_get_authorize_input__valid(self):
        in_json = """
            {
                "clientUUID": "62fcb148-76cf-45d2-9781-a09b95b309d9",
                "ipIsIPv6": false,
                "clientIP": "88.200.23.23",
                "targetIP": "88.200.23.30",
                "targetProtocol": "TCP",
                "targetPortStart": 80,
                "targetPortEnd": 1000
            }
            """
        f = io.StringIO(in_json)
        ai = authorization.get_authorize_input(f)

        self.assertEqual(ai.clientUUID, "62fcb148-76cf-45d2-9781-a09b95b309d9")
        self.assertEqual(ai.ipIsIPv6, False)
        self.assertEqual(ai.clientIP, "88.200.23.23")
        self.assertEqual(ai.targetIP, "88.200.23.30")
        self.assertEqual(ai.targetProtocol, "TCP")
        self.assertEqual(ai.targetPortStart, 80)
        self.assertEqual(ai.targetPortEnd, 1000)

    def test_get_authorize_input__missing_targetPortEnd(self):
        in_json = """
            {
                "clientUUID": "62fcb148-76cf-45d2-9781-a09b95b309d9",
                "ipIsIPv6": false,
                "clientIP": "88.200.23.23",
                "targetIP": "88.200.23.30",
                "targetProtocol": "TCP",
                "targetPortStart": 80
            }
            """
        f = io.StringIO(in_json)
        ai = authorization.get_authorize_input(f)
        valid, _ = ai.valid()
        self.assertFalse(valid)

    def test_write_authorize_output(self):
        f = io.StringIO()
        out = authorization.AuthorizationOutput()
        out.duration = 45

        authorization.write_authorize_output(f, out)

        expect = """{"duration": 45}"""
        self.assertEqual(f.getvalue(), expect)


if __name__ == '__main__':
    unittest.main()
