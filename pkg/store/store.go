package store

import (
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"

	"github.com/viveksinghggits/akcess/pkg/utils"
)

type Store interface {
	Write(*akcessConfig) error
	Close() error
	List() ([]akcessConfig, error)
	DeleteWithID(string) error
}

type akcessConfig struct {
	Id        string    `yaml:"id"`
	CreatedAt time.Time `yaml:"createdAt"`
	Namespace string    `yaml:"namespace"`
}

type FileStore struct {
	file *os.File
}

func NewAkcessConfig(id, namespace string) *akcessConfig {
	return &akcessConfig{
		Id:        id,
		CreatedAt: time.Now(),
		Namespace: namespace,
	}
}

func NewFileStore() (*FileStore, error) {
	fileName, fileRoot := utils.FilePath()
	// if dir is not available create the dir
	if _, err := os.Stat(fmt.Sprintf("%s/.%s", fileRoot, utils.Name)); err != nil {
		// create the dir
		fmt.Println("creating dir")
		if err := os.MkdirAll(fmt.Sprintf("%s/.%s", fileRoot, utils.Name), 0700); err != nil {
			return nil, errors.Wrapf(err, "Creating directory %s", fileRoot)
		}
	}

	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "opening file")
	}
	return &FileStore{
		file: f,
	}, nil
}

func (f *FileStore) Write(a *akcessConfig) error {
	list := []*akcessConfig{a}
	out, err := yaml.Marshal(list)
	if err != nil {
		return errors.Wrap(err, "marshalling data into yaml")
	}

	_, err = fmt.Fprint(f.file, string(out))
	return errors.Wrap(err, "writing data to existing file")
}

func (f *FileStore) Close() error {
	return f.file.Close()
}

func (f *FileStore) List() ([]akcessConfig, error) {
	data, err := os.ReadFile(f.file.Name())
	if err != nil {
		return nil, errors.Wrap(err, "there are chances that you have not run the command yet")
	}
	var confList []akcessConfig
	if err := yaml.Unmarshal(data, &confList); err != nil {
		return nil, errors.Wrap(err, "Unmarshalling data while listing")
	}

	return confList, nil
}

func (f *FileStore) DeleteWithID(id string) error {
	configs, err := f.List()
	if err != nil {
		return err
	}

	newList := make([]akcessConfig, 0, len(configs))
	for _, v := range configs {
		if !(v.Id == id) {
			newList = append(newList, v)
		}
	}

	// we will have to open file in truncate mode
	file, err := os.OpenFile(f.file.Name(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	out, err := yaml.Marshal(newList)
	if err != nil {
		return errors.Wrap(err, "marshalling data into yaml")
	}

	updated := string(out)

	if len(newList) == 0 {
		updated = ""
	}

	_, err = fmt.Fprint(file, updated)
	return err
}
