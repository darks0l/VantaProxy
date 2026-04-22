package notifications

import (
	"log/slog"
	"sync"
)

// Channel represents a notification channel (e.g. SSE)
type Channel interface {
	// Name returns the channel identifier
	Name() string
	// Notify sends an event to this channel
	Notify(event Event) error
}

// Dispatcher manages multiple notification channels and broadcasts events
type Dispatcher struct {
	channels map[string]Channel
	mu       sync.RWMutex
}

// NewDispatcher creates a new notification dispatcher
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		channels: make(map[string]Channel),
	}
}

// RegisterChannel adds a new notification channel
func (d *Dispatcher) RegisterChannel(channel Channel) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.channels[channel.Name()] = channel
	slog.Info("registered notification channel", "channel", channel.Name())
}

// UnregisterChannel removes a notification channel
func (d *Dispatcher) UnregisterChannel(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.channels, name)
	slog.Info("unregistered notification channel", "channel", name)
}

// Broadcast sends an event to all registered channels
func (d *Dispatcher) Broadcast(event Event) {
	d.mu.RLock()
	channels := make([]Channel, 0, len(d.channels))
	for _, ch := range d.channels {
		channels = append(channels, ch)
	}
	d.mu.RUnlock()

	// Send to all channels in parallel
	var wg sync.WaitGroup
	for _, ch := range channels {
		wg.Add(1)
		go func(channel Channel) {
			defer wg.Done()
			if err := channel.Notify(event); err != nil {
				slog.Error("error notifying channel", "channel", channel.Name(), "error", err)
			}
		}(ch)
	}
	wg.Wait()
}

// BroadcastToChannel sends an event to a specific channel
func (d *Dispatcher) BroadcastToChannel(channelName string, event Event) error {
	d.mu.RLock()
	channel, exists := d.channels[channelName]
	d.mu.RUnlock()

	if !exists {
		slog.Warn("channel not found", "channel", channelName)
		return nil
	}

	return channel.Notify(event)
}

// HasChannel checks if a channel is registered
func (d *Dispatcher) HasChannel(name string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, exists := d.channels[name]
	return exists
}
