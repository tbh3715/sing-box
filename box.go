package box

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental"
	"github.com/sagernet/sing-box/experimental/libbox/platform"
	"github.com/sagernet/sing-box/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	P "github.com/sagernet/sing-box/provider"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.Service = (*Box)(nil)

type Box struct {
	createdAt    time.Time
	router       adapter.Router
	inbounds     []adapter.Inbound
	outbounds    []adapter.Outbound
	providers    []adapter.OutboundProvider
	logFactory   log.Factory
	logger       log.ContextLogger
	preServices  map[string]adapter.Service
	postServices map[string]adapter.Service
	done         chan struct{}
}

type Options struct {
	option.Options
	Context           context.Context
	PlatformInterface platform.Interface
	PlatformLogWriter log.PlatformWriter
}

func New(options Options) (*Box, error) {
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = service.ContextWithDefaultRegistry(ctx)
	ctx = pause.ContextWithDefaultManager(ctx)
	createdAt := time.Now()
	experimentalOptions := common.PtrValueOrDefault(options.Experimental)
	applyDebugOptions(common.PtrValueOrDefault(experimentalOptions.Debug))
	var needClashAPI bool
	var needV2RayAPI bool
	if experimentalOptions.ClashAPI != nil || options.PlatformLogWriter != nil {
		needClashAPI = true
	}
	if experimentalOptions.V2RayAPI != nil && experimentalOptions.V2RayAPI.Listen != "" {
		needV2RayAPI = true
	}
	var defaultLogWriter io.Writer
	if options.PlatformInterface != nil {
		defaultLogWriter = io.Discard
	}
	logFactory, err := log.New(log.Options{
		Context:        ctx,
		Options:        common.PtrValueOrDefault(options.Log),
		Observable:     needClashAPI,
		DefaultWriter:  defaultLogWriter,
		BaseTime:       createdAt,
		PlatformWriter: options.PlatformLogWriter,
	})
	if err != nil {
		return nil, E.Cause(err, "create log factory")
	}
	router, err := route.NewRouter(
		ctx,
		logFactory,
		common.PtrValueOrDefault(options.Route),
		common.PtrValueOrDefault(options.DNS),
		common.PtrValueOrDefault(options.NTP),
		options.Inbounds,
		options.PlatformInterface,
	)
	if err != nil {
		return nil, E.Cause(err, "parse route options")
	}
	inbounds := make([]adapter.Inbound, 0, len(options.Inbounds))
	outbounds := []adapter.Outbound{}
	providers := make([]adapter.OutboundProvider, 0, len(options.OutboundProviders))
	for i, inboundOptions := range options.Inbounds {
		var in adapter.Inbound
		var tag string
		if inboundOptions.Tag != "" {
			tag = inboundOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		in, err = inbound.New(
			ctx,
			router,
			logFactory.NewLogger(F.ToString("inbound/", inboundOptions.Type, "[", tag, "]")),
			inboundOptions,
			options.PlatformInterface,
		)
		if err != nil {
			return nil, E.Cause(err, "parse inbound[", i, "]")
		}
		inbounds = append(inbounds, in)
	}
	for i, outboundProvderOptions := range options.OutboundProviders {
		var provider adapter.OutboundProvider
		var tag string
		if outboundProvderOptions.Tag != "" {
			tag = outboundProvderOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		provider, err = P.New(
			ctx,
			router,
			logFactory.NewLogger(F.ToString("provider", "[", tag, "]")),
			outboundProvderOptions,
		)
		if err != nil {
			return nil, E.Cause(err, "parse outbound provider[", i, "]")
		}
		providers = append(providers, provider)
	}
	OUTBOUNDLESS, _ := outbound.New(
		ctx,
		router,
		logFactory.NewLogger(F.ToString("outbound/direct[OUTBOUNDLESS]")),
		"OUTBOUNDLESS",
		option.Outbound{Type: "direct", Tag: "OUTBOUNDLESS"})
	outbounds = append(outbounds, OUTBOUNDLESS)
	for i, outboundOptions := range options.Outbounds {
		var out adapter.Outbound
		var tag string
		if outboundOptions.Tag != "" {
			tag = outboundOptions.Tag
		} else {
			tag = F.ToString(i)
		}
		out, err = outbound.New(
			ctx,
			router,
			logFactory.NewLogger(F.ToString("outbound/", outboundOptions.Type, "[", tag, "]")),
			tag,
			outboundOptions)
		if err != nil {
			return nil, E.Cause(err, "parse outbound[", i, "]")
		}
		outbounds = append(outbounds, out)
	}
	err = router.Initialize(inbounds, providers, outbounds)
	if err != nil {
		return nil, err
	}
	if options.PlatformInterface != nil {
		err = options.PlatformInterface.Initialize(ctx, router)
		if err != nil {
			return nil, E.Cause(err, "initialize platform interface")
		}
	}
	preServices := make(map[string]adapter.Service)
	postServices := make(map[string]adapter.Service)
	if needClashAPI {
		clashAPIOptions := common.PtrValueOrDefault(experimentalOptions.ClashAPI)
		clashAPIOptions.ModeList = experimental.CalculateClashModeList(options.Options)
		clashServer, err := experimental.NewClashServer(ctx, router, logFactory.(log.ObservableFactory), clashAPIOptions)
		if err != nil {
			return nil, E.Cause(err, "create clash api server")
		}
		router.SetClashServer(clashServer)
		preServices["clash api"] = clashServer
	}
	if needV2RayAPI {
		v2rayServer, err := experimental.NewV2RayServer(logFactory.NewLogger("v2ray-api"), common.PtrValueOrDefault(experimentalOptions.V2RayAPI))
		if err != nil {
			return nil, E.Cause(err, "create v2ray api server")
		}
		router.SetV2RayServer(v2rayServer)
		preServices["v2ray api"] = v2rayServer
	}
	return &Box{
		router:       router,
		inbounds:     inbounds,
		outbounds:    outbounds,
		providers:    providers,
		createdAt:    createdAt,
		logFactory:   logFactory,
		logger:       logFactory.Logger(),
		preServices:  preServices,
		postServices: postServices,
		done:         make(chan struct{}),
	}, nil
}

func (s *Box) PreStart() error {
	err := s.preStart()
	if err != nil {
		// TODO: remove catch error
		defer func() {
			v := recover()
			if v != nil {
				log.Error(E.Cause(err, "origin error"))
				debug.PrintStack()
				panic("panic on early close: " + fmt.Sprint(v))
			}
		}()
		s.Close()
		return err
	}
	s.logger.Info("sing-box pre-started (", F.Seconds(time.Since(s.createdAt).Seconds()), "s)")
	return nil
}

func (s *Box) Start() error {
	err := s.start()
	if err != nil {
		// TODO: remove catch error
		defer func() {
			v := recover()
			if v != nil {
				log.Error(E.Cause(err, "origin error"))
				debug.PrintStack()
				panic("panic on early close: " + fmt.Sprint(v))
			}
		}()
		s.Close()
		return err
	}
	s.logger.Info("sing-box started (", F.Seconds(time.Since(s.createdAt).Seconds()), "s)")
	return nil
}

func (s *Box) preStart() error {
	for serviceName, service := range s.preServices {
		if preService, isPreService := service.(adapter.PreStarter); isPreService {
			s.logger.Trace("pre-start ", serviceName)
			err := preService.PreStart()
			if err != nil {
				return E.Cause(err, "pre-starting ", serviceName)
			}
		}
	}
	err := s.startOutbounds()
	if err != nil {
		return err
	}
	for i, p := range s.providers {
		var tag string
		if p.Tag() == "" {
			tag = F.ToString(i)
		} else {
			tag = p.Tag()
		}
		p.Start()
		s.logger.Trace("initializing outbound provider/", p.Type(), "[", tag, "]")
	}
	return s.router.Start()
}

func (s *Box) start() error {
	err := s.preStart()
	if err != nil {
		return err
	}
	for serviceName, service := range s.preServices {
		s.logger.Trace("starting ", serviceName)
		err = service.Start()
		if err != nil {
			return E.Cause(err, "start ", serviceName)
		}
	}
	for i, in := range s.inbounds {
		var tag string
		if in.Tag() == "" {
			tag = F.ToString(i)
		} else {
			tag = in.Tag()
		}
		s.logger.Trace("initializing inbound/", in.Type(), "[", tag, "]")
		err = in.Start()
		if err != nil {
			return E.Cause(err, "initialize inbound/", in.Type(), "[", tag, "]")
		}
	}
	return nil
}

func (s *Box) postStart() error {
	for serviceName, service := range s.postServices {
		s.logger.Trace("starting ", service)
		err := service.Start()
		if err != nil {
			return E.Cause(err, "start ", serviceName)
		}
	}
	for serviceName, service := range s.outbounds {
		if lateService, isLateService := service.(adapter.PostStarter); isLateService {
			s.logger.Trace("post-starting ", service)
			err := lateService.PostStart()
			if err != nil {
				return E.Cause(err, "post-start ", serviceName)
			}
		}
	}
	return nil
}

func (s *Box) Close() error {
	select {
	case <-s.done:
		return os.ErrClosed
	default:
		close(s.done)
	}
	var errors error
	for serviceName, service := range s.postServices {
		s.logger.Trace("closing ", serviceName)
		errors = E.Append(errors, service.Close(), func(err error) error {
			return E.Cause(err, "close ", serviceName)
		})
	}
	for i, in := range s.inbounds {
		s.logger.Trace("closing inbound/", in.Type(), "[", i, "]")
		errors = E.Append(errors, in.Close(), func(err error) error {
			return E.Cause(err, "close inbound/", in.Type(), "[", i, "]")
		})
	}
	for i, out := range s.outbounds {
		s.logger.Trace("closing outbound/", out.Type(), "[", i, "]")
		errors = E.Append(errors, common.Close(out), func(err error) error {
			return E.Cause(err, "close outbound/", out.Type(), "[", i, "]")
		})
	}
	for i, prov := range s.providers {
		for j, out := range prov.Outbounds() {
			s.logger.Trace("closing provider/", prov.Type(), "[", i, "]", " outbound/", out.Type(), "[", j, "]")
			errors = E.Append(errors, common.Close(out), func(err error) error {
				return E.Cause(err, "close provider/", prov.Type(), "[", i, "]", " outbound/", out.Type(), "[", j, "]")
			})
		}
		s.logger.Trace("closing provider/", prov.Type(), "[", i, "]")
		errors = E.Append(errors, common.Close(prov), func(err error) error {
			return E.Cause(err, "close provider/", prov.Type(), "[", i, "]")
		})
	}
	s.logger.Trace("closing router")
	if err := common.Close(s.router); err != nil {
		errors = E.Append(errors, err, func(err error) error {
			return E.Cause(err, "close router")
		})
	}
	for serviceName, service := range s.preServices {
		s.logger.Trace("closing ", serviceName)
		errors = E.Append(errors, service.Close(), func(err error) error {
			return E.Cause(err, "close ", serviceName)
		})
	}
	s.logger.Trace("closing log factory")
	if err := common.Close(s.logFactory); err != nil {
		errors = E.Append(errors, err, func(err error) error {
			return E.Cause(err, "close log factory")
		})
	}
	return errors
}

func (s *Box) Router() adapter.Router {
	return s.router
}
