package tun

import "time"

const maxPendingICMPEchoReply = 256

func (s *stack) scheduleICMPEchoReply(delay time.Duration, reply func()) bool {
	if delay <= 0 || delay > maxICMPProbeDelay || reply == nil {
		return false
	}
	s.icmpTimerAccess.Lock()
	defer s.icmpTimerAccess.Unlock()
	if s.icmpClosing || s.icmpReplyCount >= maxPendingICMPEchoReply {
		return false
	}
	if s.icmpTimers == nil {
		s.icmpTimers = make(map[uint64]*time.Timer)
	}
	s.icmpNextTimerID++
	timerID := s.icmpNextTimerID
	s.icmpReplyCount++
	s.icmpTimers[timerID] = time.AfterFunc(delay, func() {
		s.icmpTimerAccess.Lock()
		delete(s.icmpTimers, timerID)
		if s.icmpClosing {
			s.icmpReplyCount--
			s.icmpTimerAccess.Unlock()
			return
		}
		s.icmpReplyWG.Add(1)
		s.icmpTimerAccess.Unlock()
		defer func() { s.icmpTimerAccess.Lock(); s.icmpReplyCount--; s.icmpTimerAccess.Unlock(); s.icmpReplyWG.Done() }()
		reply()
	})
	return true
}

func (s *stack) stopICMPEchoReplies() {
	s.icmpTimerAccess.Lock()
	s.icmpClosing = true
	for timerID, timer := range s.icmpTimers {
		if timer.Stop() {
			s.icmpReplyCount--
		}
		delete(s.icmpTimers, timerID)
	}
	s.icmpTimerAccess.Unlock()
	s.icmpReplyWG.Wait()
}
