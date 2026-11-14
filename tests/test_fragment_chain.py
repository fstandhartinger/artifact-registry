"""a#41d6d2 (14 Nov 2026): fragments spoken during a long tool call are ONE question; a real miss stays flagged. Pure: sessions.diagnose, no database."""
import datetime as dt, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))
import sessions as S

T0 = dt.datetime(2026, 11, 14, 13, 24, 23, tzinfo=dt.timezone.utc)
def ev(sec, seq, type_, turn, **data): return {'ts': T0 + dt.timedelta(seconds=sec), 'seq': seq, 'source': 'gateway', 'turn': turn, 'type': type_, 'data': data}
META = {'id': 'a#41d6d2', 'kind': 'voice'}

class FragmentChain(unittest.TestCase):
    def incident(self):
        # turn 4 answered, then search_files runs 21 s; turns 5 and 6 are fragments of one sentence, turn 7 (8 s later) gets the answer
        return [ev(0, 1, 'transcript.user.final', 4, text='Wären die von diesem Prinzip erkannt worden?'), ev(2, 2, 'transcript.assistant.final', 4, text='Die genauen Urteile habe ich nicht als fertige Liste.'),
            ev(2, 3, 'tool.call', 4, name='search_files', call_id='c1'), ev(23, 4, 'tool.done', 4, call_id='c1'), ev(23, 5, 'watchdog.adapter', 4, n=1),
            ev(25, 6, 'transcript.user.final', 5, text='Äh, es wäre wichtig zu verstehen, ob ein Miner herausfindet, dass irgendwo ein nicht bekanntgegebener, ähm, Abstammungs...'),
            ev(36, 7, 'transcript.user.final', 6, text='Vorfall vorliegt.'),
            ev(43, 8, 'transcript.user.final', 7, text='Und dann habe ich wieder das Problem, dass ich Entscheidungen ändern muss.'),
            ev(44, 9, 'transcript.assistant.final', 7, text='Das ist der Punkt, den die Quellen direkt ansprechen.'), ev(120, 10, 'session.stop', None)]
    def test_incident_is_not_flagged(self):
        d = S.diagnose(META, self.incident())
        self.assertEqual(d['unanswered'], []); self.assertFalse(d['flagged'])
        self.assertEqual([(r['turn'], r['answered']) for r in d['turns']], [(4, True), (5, True)])
        self.assertEqual(d['turns'][1]['fragments'], 3); self.assertIn('Vorfall vorliegt.', d['turns'][1]['question'])
    def test_chain_without_answer_is_one_unanswered_question(self):
        d = S.diagnose(META, self.incident()[:7] + [ev(100, 8, 'session.stop', None)])
        self.assertEqual(len(d['unanswered']), 1); self.assertTrue(d['flagged']); self.assertEqual(d['unanswered'][0]['fragments'], 2)
        self.assertIn('1 Frage(n) ohne Antwort', d['flag_reason'])
    def test_far_apart_questions_are_not_merged(self):
        events = [ev(0, 1, 'transcript.user.final', 1, text='Erste ernsthafte Frage ohne Antwort?'), ev(200, 2, 'transcript.user.final', 2, text='Zweite ernsthafte Frage ohne Antwort?'),
            ev(205, 3, 'transcript.assistant.final', 2, text='Hier ist die Antwort auf die zweite Frage.'), ev(240, 4, 'session.stop', None)]
        d = S.diagnose(META, events)
        self.assertEqual([r['turn'] for r in d['unanswered']], [1]); self.assertTrue(d['flagged'])
    def test_announcement_then_new_question_stays_a_miss(self):
        events = [ev(0, 1, 'transcript.user.final', 1, text='Kannst du das aufzeichnen?'), ev(1, 2, 'transcript.assistant.final', 1, text='Ich schaue nach.'),
            ev(10, 3, 'transcript.user.final', 2, text='Und was ist mit dem anderen Thema?'), ev(12, 4, 'transcript.assistant.final', 2, text='Dazu steht im Konzept ein eigener Abschnitt.'), ev(30, 5, 'session.stop', None)]
        d = S.diagnose(META, events)
        self.assertEqual([r['turn'] for r in d['unanswered']], [1]); self.assertTrue(d['turns'][0]['announcement_only'])
    def test_marking_with_nothing_said_after_it_stays_a_finding(self):
        events = [ev(0, 1, 'transcript.user.final', 1, text='Schau dir das hier an bitte.'), ev(2, 2, 'transcript.assistant.final', 1, text='Ja, ich sehe ein Diagramm mit drei Kästen.'),
            ev(5, 3, 'transcript.user.final', 2, text='[Markierung] etwas markiert', marker=True), ev(30, 4, 'session.stop', None)]
        d = S.diagnose(META, events)
        self.assertEqual([r['turn'] for r in d['unanswered']], [2])
    def test_spoken_context_around_a_marking_joins_one_question(self):
        # the marking was seen (an answer follows): the words before and after it are one thought, answered by the one answer
        events = [ev(0, 1, 'transcript.user.final', 1, text='Schau dir das hier an bitte.'), ev(5, 2, 'transcript.user.final', 2, text='[Markierung] etwas markiert', marker=True),
            ev(8, 3, 'transcript.user.final', 3, text='Was ist das da?'), ev(10, 4, 'transcript.assistant.final', 3, text='Das ist ein Diagramm.'), ev(30, 5, 'session.stop', None)]
        d = S.diagnose(META, events)
        self.assertEqual(d['unanswered'], [])

if __name__ == '__main__': unittest.main()
