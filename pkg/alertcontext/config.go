package alertcontext

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// this file is here to avoid circular dependencies between the configuration and the hub

// HubItemWrapper is a wrapper around a hub item to unmarshal only the context part
// because there are other fields like name etc.
type HubItemWrapper struct {
	Context map[string][]string `yaml:"context"`
}


// mergeContextFromItem merges the context from an item into the context to send to the console.
func mergeContextFromItem(toSend map[string][]string, item *cwhub.Item) error {
	filePath := item.State.LocalPath
	log.Tracef("loading console context from %s", filePath)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	wrapper := &HubItemWrapper{}

	err = yaml.Unmarshal(content, wrapper)
	if err != nil {
		return fmt.Errorf("%s: %w", filePath, err)
	}

	for k, v := range wrapper.Context {
		for _, s := range v {
			if !slices.Contains(toSend[k], s) {
				toSend[k] = append(toSend[k], s)
			}
		}
	}

	return nil
}

// mergeContextFromFile merges the context from a file into the context to send to the console.
func mergeContextFromFile(toSend map[string][]string, filePath string) error {
	log.Tracef("loading console context from %s", filePath)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	newContext := make(map[string][]string, 0)

	err = yaml.Unmarshal(content, newContext)
	if err != nil {
		return fmt.Errorf("%s: %w", filePath, err)
	}

	for k, v := range newContext {
		for _, s := range v {
			if !slices.Contains(toSend[k], s) {
				toSend[k] = append(toSend[k], s)
			}
		}
	}

	return nil
}


// LoadConsoleContext loads the context from the hub and the file console_context_path.
func LoadConsoleContext(c *csconfig.Config, hub *cwhub.Hub) error {
	c.Crowdsec.ContextToSend = make(map[string][]string, 0)

	// load the hub context
	
	items, err := hub.GetInstalledItems(cwhub.CONTEXTS)
	if err != nil {
		return err
	}

	for _, item := range items {
		// context in item files goes under the key 'context'
		if err = mergeContextFromItem(c.Crowdsec.ContextToSend, item); err != nil {
			return err
		}
	}

	ignoreMissing := false

	if c.Crowdsec.ConsoleContextPath != "" {
		// if it's provided, it must exist
		if _, err = os.Stat(c.Crowdsec.ConsoleContextPath); err != nil {
			return fmt.Errorf("while checking console_context_path: %w", err)
		}
	} else {
		c.Crowdsec.ConsoleContextPath = filepath.Join(c.ConfigPaths.ConfigDir, "console", "context.yaml")
		ignoreMissing = true
	}

	if err = mergeContextFromFile(c.Crowdsec.ContextToSend, c.Crowdsec.ConsoleContextPath); err != nil {
		if !ignoreMissing || !os.IsNotExist(err) {
			return err
		}
	}

	feedback, err := json.Marshal(c.Crowdsec.ContextToSend)
	if err != nil {
		return fmt.Errorf("marshaling console context: %s", err)
	}

	log.Debugf("console context to send: %s", feedback)

	return nil
}
