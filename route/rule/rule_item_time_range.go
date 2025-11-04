package rule

import (
	"context"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
)

var _ RuleItem = (*TimeRangeItem)(nil)

type TimeRangeItem struct {
	timeFunc func() time.Time
	ranges   []timeRange
}

type timeRange struct {
	start, end time.Time
}

func (t *timeRange) String() string {
	return t.start.Format(time.TimeOnly) + "-" + t.end.Format(time.TimeOnly)
}

func (t *timeRange) match(now time.Time) bool {
	// [start, end)
	return !now.Before(t.start) && !now.After(t.end)
}

func NewTimeRangeItem(ctx context.Context, rawRanges []option.TimeRange, timeZone string) (*TimeRangeItem, error) {
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	var location *time.Location
	if timeZone != "" {
		var err error
		location, err = time.LoadLocation(timeZone)
		if err != nil {
			return nil, E.Cause(err, "load time zone")
		}
	} else {
		location = timeFunc().Location()
	}
	newRanges := make([]timeRange, 0, len(rawRanges))
	for _, rawRange := range rawRanges {
		start := copyTimeOnly(rawRange.Start, location)
		end := copyTimeOnly(rawRange.End, location)
		if !start.After(end) {
			newRanges = append(newRanges, timeRange{
				start: start,
				end:   end,
			})
			continue
		}
		// Across one day
		newRange0 := timeRange{
			start: start,
			end:   time.Date(0, 0, 0, 23, 59, 59, 59, location),
		}
		newRange1 := timeRange{
			start: time.Date(0, 0, 0, 0, 0, 0, 0, location),
			end:   end,
		}
		newRanges = append(newRanges, newRange0, newRange1)
	}
	return &TimeRangeItem{
		timeFunc: timeFunc,
		ranges:   newRanges,
	}, nil
}

func copyTimeOnly(raw time.Time, location *time.Location) time.Time {
	return time.Date(0, 0, 0, raw.Hour(), raw.Minute(), raw.Second(), raw.Nanosecond(), location)
}

func (t *TimeRangeItem) Match(metadata *adapter.InboundContext) bool {
	now := t.timeFunc()
	location := *now.Location()
	now = copyTimeOnly(now, &location)
	return common.Any(t.ranges, func(it timeRange) bool {
		return it.match(now)
	})
}

func (t *TimeRangeItem) String() string {
	itemsString := common.Map(t.ranges, func(it timeRange) string {
		return it.String()
	})
	return "time_range=" + "[" + strings.Join(itemsString, ",") + "]"
}
