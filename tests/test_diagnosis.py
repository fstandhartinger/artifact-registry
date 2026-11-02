import unittest
from datetime import datetime, timedelta, timezone

import sessions as S

T0 = datetime(2026, 11, 2, 15, 0, tzinfo=timezone.utc)

def ev(seq, s, typ, turn=None, **data):
    return {'seq': seq, 'ts': T0+timedelta(seconds=s), 'source': 'gateway', 'turn': turn, 'type': typ, 'data': data}

class DiagnosisFragments(unittest.TestCase):
    def run_events(self, events):
        events = events+[ev(999, 200, 'session.stop')]
        return S.diagnose({'id': 'a#abcdef', 'started_at': T0}, events)

    def test_early_final_fragment_is_one_question(self):
        # a#7f54a5 shape: the vendor finalised the half sentence twice, the full one got the answer
        d = self.run_events([
            ev(1, 10, 'turn.user.start', 5), ev(2, 10, 'transcript.user.final', 5, text='Wir nehmen das jetzt auf, weil wir'),
            ev(3, 14, 'turn.user.start', 6), ev(4, 14, 'transcript.user.final', 6, text='Wir nehmen das jetzt auf, weil wir eine Fehlerbehebung'),
            ev(5, 17, 'turn.user.start', 7), ev(6, 17, 'transcript.user.final', 7, text='Wir nehmen das jetzt auf, weil wir eine Fehlerbehebung machen.'),
            ev(7, 19, 'transcript.assistant.final', 7, text='Verstanden.')])
        self.assertEqual(d['unanswered'], [])
        self.assertFalse(d['flagged'])
        self.assertEqual([t.get('superseded', False) for t in d['turns']], [True, True, False])

    def test_talked_over_and_answered(self):
        d = self.run_events([
            ev(1, 10, 'turn.user.start', 8), ev(2, 10, 'transcript.user.final', 8, text='[Markierung] etwas markiert'),
            ev(3, 11.5, 'turn.user.start', 9), ev(4, 11.5, 'transcript.user.final', 9, text='Was passiert, wenn ich etwas markiere?'),
            ev(5, 13, 'transcript.assistant.final', 9, text='Ich sehe die Markierung.')])
        self.assertEqual(d['unanswered'], [])

    def test_real_unanswered_question_still_flagged(self):
        d = self.run_events([
            ev(1, 10, 'turn.user.start', 1), ev(2, 10, 'transcript.user.final', 1, text='Welche Mail kam zuletzt von TNG?'),
            ev(3, 40, 'turn.user.start', 2), ev(4, 40, 'transcript.user.final', 2, text='Hallo, wieso kommt keine Antwort?')])
        self.assertEqual(len(d['unanswered']), 2)
        self.assertTrue(d['flagged'])

if __name__ == '__main__': unittest.main()
