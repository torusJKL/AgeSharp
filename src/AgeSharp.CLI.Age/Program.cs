using System.Security.Cryptography;

using AgeSharp.CommandLine;

using AgeSharp.Core;

namespace AgeSharp.CLI;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var parser = new CommandLineParser("age");

        parser.AddUsage("[--encrypt] (-r RECIPIENT | -R PATH | -p)... [--armor] [-o OUTPUT] [INPUT]");
        parser.AddUsage("--decrypt [-i PATH]... [-o OUTPUT] [INPUT]");

        var encryptOption = parser.AddFlag<bool>(
            ["-e", "--encrypt"],
            "Encrypt the input to the output. Default if omitted.");

        var decryptOption = parser.AddFlag<bool>(
            ["-d", "--decrypt"],
            "Decrypt the input to the output.");

        var outputOption = parser.AddOption(
            ["-o", "--output"],
            "Write the result to the file at path OUTPUT.");

        var recipientOption = parser.AddMultiValueOption(
            ["-r", "--recipient"],
            "Encrypt to the specified RECIPIENT. Can be repeated.");

        var recipientsFileOption = parser.AddMultiValueOption(
            ["-R", "--recipients-file"],
            "Encrypt to recipients listed at PATH. Can be repeated.");

        var identityOption = parser.AddMultiValueOption(
            ["-i", "--identity"],
            "Use the identity file at PATH. Can be repeated.");

        var armorOption = parser.AddFlag<bool>(
            ["-a", "--armor"],
            "Use ASCII armor (PEM encoding) for the output.");

        var passphraseOption = parser.AddFlag<bool>(
            ["-p", "--passphrase"],
            "Encrypt with a passphrase.");

        var versionOption = parser.AddFlag<bool>(
            ["--version"],
            "Print version information.");

        var inputArgument = parser.AddArgument<string?>(
            "input",
            "Input file to encrypt or decrypt. Defaults to stdin.",
            defaultValueFactory: () => null);

        var result = parser.Parse(args);

        if (args.Contains("--help") || args.Contains("-h"))
        {
            return await parser.InvokeAsync(["--help"]);
        }

        if (args.Contains("--version"))
        {
            Console.WriteLine(AgeSharp.Core.Version.GetVersion());
            return 0;
        }

        if (result.Errors.Count > 0)
        {
            foreach (var error in result.Errors)
            {
                Console.Error.WriteLine(error.Message);
            }
            return 1;
        }

        var encrypt = result.GetValueForOption(encryptOption);
        var decrypt = result.GetValueForOption(decryptOption);
        var output = result.GetValueForOption(outputOption);
        var recipients = result.GetValueForOption(recipientOption) ?? [];
        var recipientsFiles = result.GetValueForOption(recipientsFileOption) ?? [];
        var identities = result.GetValueForOption(identityOption) ?? [];
        var armor = result.GetValueForOption(armorOption);
        var passphrase = result.GetValueForOption(passphraseOption);
        var input = result.GetValueForArgument(inputArgument);

        bool hasInput = encrypt || decrypt ||
                        false == string.IsNullOrEmpty(output) ||
                        recipients.Length > 0 || recipientsFiles.Length > 0 ||
                        identities.Length > 0 || passphrase ||
                        false == string.IsNullOrEmpty(input);

        if (!hasInput)
        {
            return await parser.InvokeAsync(["--help"]);
        }

        if (decrypt)
        {
            await Decrypt(output, identities, input);
        }
        else if (passphrase)
        {
            if (recipients.Length > 0 || recipientsFiles.Length > 0)
            {
                Console.Error.WriteLine("Error: -p/--passphrase and -r/--recipient/-R/--recipients-file cannot be used together");
                return 1;
            }
            await EncryptWithPassphrase(output, armor, input);
        }
        else if (recipients.Length > 0 || recipientsFiles.Length > 0)
        {
            await Encrypt(output, recipients, recipientsFiles, armor, input);
        }
        else
        {
            Console.Error.WriteLine("Error: at least one recipient is required");
            return 1;
        }

        return 0;
    }

    private static async Task Encrypt(string? output, string[] recipients, string[] recipientsFiles, bool armor, string? input)
    {
        var recipientList = new List<IRecipient>();

        foreach (var r in recipients)
        {
            recipientList.Add(AgeParser.ParseRecipient(r));
        }

        foreach (var file in recipientsFiles)
        {
            foreach (var r in AgeParser.ParseRecipientsFile(file))
            {
                recipientList.Add(r);
            }
        }

        if (recipientList.Count == 0)
        {
            Console.Error.WriteLine("Error: at least one recipient is required");
            Environment.Exit(1);
        }

        Stream inputStream;
        if (string.IsNullOrEmpty(input))
        {
            if (Console.IsInputRedirected)
            {
                var memStream = new MemoryStream();
                await Console.OpenStandardInput().CopyToAsync(memStream);
                memStream.Position = 0;
                inputStream = memStream;
            }
            else
            {
                Console.Error.WriteLine("Error: no input specified and stdin is not redirected");
                Environment.Exit(1);
                return;
            }
        }
        else
        {
            if (false == File.Exists(input))
            {
                Console.Error.WriteLine($"Error: input file not found: {input}");
                Environment.Exit(1);
                return;
            }
            inputStream = File.OpenRead(input);
        }

        using (inputStream)
        {
            Stream outputStream;

            if (string.IsNullOrEmpty(output))
            {
                if (Console.IsOutputRedirected)
                {
                    outputStream = Console.OpenStandardOutput();
                }
                else
                {
                    Console.Error.WriteLine("Error: refusing to write binary data to terminal. Use -o or redirect output.");
                    Environment.Exit(1);
                    return;
                }
            }
            else
            {
                outputStream = File.Create(output);
            }

            using (outputStream)
            {
                var options = new EncryptionOptions { Armor = armor };
                await Age.EncryptAsync(inputStream, outputStream, recipientList, options);
            }
        }
    }

    private static async Task Decrypt(string? output, string[] identities, string? input)
    {
        var identityList = new List<IIdentity>();

        foreach (var file in identities)
        {
            foreach (var identity in AgeParser.ParseIdentitiesFile(file))
            {
                identityList.Add(identity);
            }
        }

        if (identityList.Count == 0)
        {
            Console.Error.WriteLine("Error: at least one identity file is required for decryption");
            Environment.Exit(1);
        }

        Stream inputStream;
        if (string.IsNullOrEmpty(input))
        {
            if (Console.IsInputRedirected)
            {
                inputStream = Console.OpenStandardInput();
            }
            else
            {
                Console.Error.WriteLine("Error: no input specified and stdin is not redirected");
                Environment.Exit(1);
                return;
            }
        }
        else
        {
            if (false == File.Exists(input))
            {
                Console.Error.WriteLine($"Error: input file not found: {input}");
                Environment.Exit(1);
                return;
            }
            inputStream = File.OpenRead(input);
        }

        using (inputStream)
        {
            Stream outputStream;

            if (string.IsNullOrEmpty(output))
            {
                outputStream = Console.OpenStandardOutput();
            }
            else
            {
                outputStream = File.Create(output);
            }

            using (outputStream)
            {
                try
                {
                    await Age.DecryptAsync(inputStream, outputStream, identityList);
                }
                catch (Core.Exceptions.AgeDecryptionException ex)
                {
                    Console.Error.WriteLine($"Error: {ex.Message}");
                    Environment.Exit(1);
                }
            }
        }
    }

    private static async Task EncryptWithPassphrase(string? output, bool armor, string? input)
    {
        var passphrase = PromptForPassphraseWithAutoGenerate();

        var recipient = AgeParser.ParseRecipient(passphrase);
        var recipientList = new List<IRecipient> { recipient };

        Stream inputStream;
        if (string.IsNullOrEmpty(input))
        {
            if (Console.IsInputRedirected)
            {
                var memStream = new MemoryStream();
                await Console.OpenStandardInput().CopyToAsync(memStream);
                memStream.Position = 0;
                inputStream = memStream;
            }
            else
            {
                Console.Error.WriteLine("Error: no input specified and stdin is not redirected");
                Environment.Exit(1);
                return;
            }
        }
        else
        {
            if (false == File.Exists(input))
            {
                Console.Error.WriteLine($"Error: input file not found: {input}");
                Environment.Exit(1);
                return;
            }
            inputStream = File.OpenRead(input);
        }

        using (inputStream)
        {
            Stream outputStream;

            if (string.IsNullOrEmpty(output))
            {
                if (Console.IsOutputRedirected)
                {
                    outputStream = Console.OpenStandardOutput();
                }
                else
                {
                    Console.Error.WriteLine("Error: refusing to write binary data to terminal. Use -o or redirect output.");
                    Environment.Exit(1);
                    return;
                }
            }
            else
            {
                outputStream = File.Create(output);
            }

            using (outputStream)
            {
                var options = new EncryptionOptions { Armor = armor };
                await Age.EncryptAsync(inputStream, outputStream, recipientList, options);
            }
        }

        CryptographicOperations.ZeroMemory(System.Text.Encoding.UTF8.GetBytes(passphrase));
    }

    private static string PromptForPassphraseWithAutoGenerate()
    {
        Console.Error.Write("Enter passphrase (leave empty to autogenerate a secure one): ");
        Console.Error.Flush();
        
        var passphrase = Console.ReadLine() ?? "";

        if (string.IsNullOrEmpty(passphrase))
        {
            passphrase = GenerateSecurePassphrase();
            Console.Error.WriteLine($"Using the autogenerated passphrase \"{passphrase}\".");
        }
        else
        {
            Console.Error.Write("Confirm passphrase: ");
            Console.Error.Flush();
            var confirm = Console.ReadLine() ?? "";
            if (confirm != passphrase)
            {
                Console.Error.WriteLine("Error: passphrases didn't match");
                Environment.Exit(1);
                return "";
            }
        }

        return passphrase;
    }

    private static string PromptForPassphrase()
    {
        Console.Write("Enter passphrase: ");
        return Console.ReadLine() ?? "";
    }

    private static string GenerateSecurePassphrase()
    {
        const string words = "abandon-action-activity-add-again-agency-agent-agree-ahead-air-force-alarm-album-alert-alike-alive-alone-amount-anchor-ancient-angle-angry-animal-annual-answer-anticipate-anxiety-any-apart-apology-appear-apple-approve-arctic-area-argue-arise-arm-army-around-arrange-arrest-arrive-arrow-art-article-assault-asset-assist-assume-attach-attack-attend-august-author-auto-autumn-average-aviation-avoid-award-aware-badly-baker-basics-basis-beach-beard-been-beer-belly-bench-better-beyond-bias-bird-bite-blind-block-blood-board-boat-body-boil-bomb-bond-bone-book-boost-border-borrow-boss-bottom-bought-bound-brain-brand-bread-breakfast-breath-bridge-brief-bright-bring-brother-brought-brown-build-burst-bus-business-busy-buy-cab-cabin-cable-cake-calf-call-calm-camp-capital-captain-car-carbon-card-career-cargo-carpet-carry-cart-case-cash-casino-catch-cattle-caught-cause-cave-cell-centre-century-certain-chair-challenge-chamber-champion-change-change- chapter-charge-chase-cheap-check-chest-chief-child-china-chip-chocolate-choice-choose-chronic-chuckle-chunk-churn-cigar-cinema-circle-circumstance-citizen-civil-claim-clarify-class-clean-clear-cleat-click-client-climb-clock-close-cloud-club-cluster-clutch-coach-coal-coast-color-come-comfort-comic-common-company-concert-condemn-conduct-confirm-congress-connect-consider-consult-continue-control-convert-convey-convince-cook-cool-copper-copy-corn-corner-correct-cost-cottage-cotton-couch-country-couple-course-cousin-cover-cow-crack-craft-crash-crawl-crazy-cream-create-creature-credible-credit-creek-crew-crime-crisp-critic-crop-cross-crouch-crowd-crucial-crude-cruise-crumb-crush-cry-crystal-cube-culture-cup-cupboard-current-curtain-curve-cushion-custom-cute-cycle-daily-dairy-dance-danger-daring-daughter-dawn-day-deal-debate-debris-decade-december-decide-decline-decorate-decrease-deer-defense-define-defy-degree-delay-deliver-demand-demise-denial-dentist-denounce-dense-deposit-derive-describe-desert-design-desire-desk-despair-destroy-detail-detect-develop-device-devote-diagram-dial-diamond-diary-dictate-diesel-diet-differ-digital-dignity-dilemma-dinner-dinosaur-direct-dirt-disagree-discover-disease-disk-dismiss-dispute-distance-disturb-diverse-divide-divorce-doctor-document-doe-dog-door-dose-double-dove-draft-drama-dramatic-draw-drawn-dream-dress-drift-drill-drink-drive-drop-drug-drum-dry-duck-dull-duly-dump-duplicate-durable-during-dust-duty-dwarf-dwell-dying-dynamite-eager-eagle-early-earth-ease-east-easy-echo-eclipse-economy-edge-edition-educate-effect-effigy-effort-egg-eight-elaborate-elbow-elder-elect-elegant-element-elephant-eleven-eliminate-elite-embark-emblem-embryo-emerge-emotion-emphasis-employ-empty-enable-enact-encounter-end-endorse-enemy-energy-enforce-engage-engine-enhance-enjoy-enlighten-enough-enrich-enroll-ensure-enter-entire-entity-entrance-entry-envelope-envy-episode-equate-equity-equivalent-era-erode-err-errand-erupt-escape-essence-estate-estimate-eternal-evade-even-event-ever-every-evict-evidence-evoke-evolve-exact-exaggerate-exceed-excel-excite-exclude-excuse-execute-exercise-exhaust-exhibit-exile-exist-exit-exotic-expand-expect-experience-explain-explode-exploit-explore-export-expose-express-extend-extract-exult-eyebrow-fabric-face-fact-faculty-fade-faint-fair-fake-fall-family-famine-fancy-fantasy-fare-farm-fast-fat-fate-fatigue-fault-favorite-fear-feast-federal-fee-feed-feel-female-fence-festival-fetch-fever-few-fiber-fiction-field-fierce-fifth-fifty-fight-figure-file-film-filter-final-finance-find-fine-finger-finish-fire-firm-first-fix-flag-flame-flash-flat-flavor-fled-flesh-flick-flight-fling-flip-float-flock-floor-flour-fluid-flush-fly-foam-focal-focus-fog-foil-fold-folk-follow-food-fool-foot-forbid-force-fork-formal-format-former-fortune-forum-fossil-foster-foul-found-fox-fragile-frail-frame-frank-fraud-freak-freeze-fresh-friction-friday-fridge-friend-fright-fringe-frock-frog-front-frost-frown-frozen-fruit-frustrate-fuel-fulfill-full-fume-fun-fungus-funny-fur-furnace-fury-fuse-fuss-future-gadget-gain-galaxy-gallery-game-garage-garbage-garden-garlic-gas-gasp-gate-gather-gauge-gave-gaze-general-genius-genre-gentle-genuine-german-gesture-ghost-giant-gift-giggle-ginger-giraffe-girl-give-glad-glance-glare-glass-glide-glimpse-globe-glory-glove-glow-glue-goat-god-gold-golf-gone-good-gorge-gospel-gossip-got-govern-gown-grab-grace-gracious-grade-grand-grandparent-grape-grass-gravity-great-green-greet-grief-grill-grim-grin-grind-grip-groan-grocery-groom-groove-gross-group-grow-growth-guard-guess-guilt-guitar-gun-gym-habit-hair-half-hall-halt-hamburger-hammer-hand-handle-harbor-hard-harm-harmony-harsh-harvest-hash-hashtag-hat-hate-haunt-have-hawk-hazard-head-heal-health-heap-hear-heart-heat-heaven-heavy-hedge-hello-helm-helmet-help-hemp-hence-herb-heritage-hero-hidden-high-hike-hill-hint-hip-historic-hold-hole-holiday-hollow-holy-home-honest-honey-honor-horse-hose-hospital-host-hotel-hour-house-hover-how-hug-huge-hull-human-humble-humor-hundred-hunger-hunt-hurdle-hurl-hurry-hurt-husband-hut-ice-icon-idea-identify-ignore-ill-illegal-illness-illustrate-image-imagine-imitate-immune-impact-impose-impress-improve-impulse-impure-include-income-incorrect-indicate-industry-inevitable-infant-infect-infinite-influence-inform-inhale-inherit-initial-inject-injure-innocent-innovate-input-insect-insert-inside-inspire-install-instance-instead-insult-intact-integrate-intellect-intend-intense-intent-interact-interest-interfere-internal-international-interpret-interrupt-intimate-introduce-invade-invent-inverse-investigate-invite-involve-iris-iron-island-issue-item-ivory-jacket-jaguar-jail-jar-jazz-jealous-jeans-jelly-job-join-joke-jolly-journey-joy-judge-juice-jumbo-jump-june-jungle-junior-junk-juror-just-keen-keep-ketchup-key-kick-kid-kidnap-kill-killer-kiss-kit-kitten-kiwi-knee-knife-knock-knoll-knot-know-labor-lack-ladder-lady-lake-lamp-lance-land-language-laptop-large-laser-last-late-later-latin-laugh-launch-laundry-lava-law-lawn-lawsuit-layer-lay-lazy-lead-leader-leaf-lean-learn-leave-lecture-left-leg-legal-legend-lemon-level-lever-liability-liberty-library-license-lid-lie-life-lift-light-like-limb-limit-lincoln-line-linen-lion-lip-listen-liter-little-live-liver-livestock-load-loaf-loan-lobby-local-locate-lock-lodge-loft-logic-loose-lorry-lose-loss-lost-lot-lottery-loud-love-loyal-lucky-lunch-lung-lure-lush-lust-lynch-mad-magic-magnetmaid-mail-main-major-make-male-mammal-man-manage-mandate-mango-manual-manufacture-many-map-marble-march-margin-marine-mark-market-marry-marsh-mart-mash-mass-massive-master-match-material-math-matrix-matter-mature-maximum-maze-meadow-mean-meant-measure-meat-mechanic-medal-medical-medicine-meet-melancholy-melody-melon-melt-member-memory-men-mend-mental-mention-mentor-merciful-mercury-merit-merry-message-metal-method-middle-might-mild-mile-milk-milli-million-mimic-mind-minimum-minor-minus-minute-miracle-mirror-mirth-misery-miss-mission-mist-mix-mocha-mode-modify-mold-moment-money-monkey-month-mood-moon-more-morning-mortal-mosque-most-mother-motion-motor-motorcycle-mould-mount-mountain-mouse-mouth-move-much-muck-mud-muffin-mule-multiple-mumble-municipal-muse-mushroom-music-must-mutual-muzzle-my-name-nap-narrate-narrow-nation-natural-nature-naval-navy-near-neat-necessary-neck-need-negative-negotiate-neighbor-neither-nephew-nerve-nest-net-network-neutral-never-new-news-newspaper-next-nice-night-noble-noise-nominee-noodle-normal-north-nose-notable-note-nothing-notice-notify-novel-now-nuclear-nudge-numb-nurse-nut-oak-obey-object-oblique-observe-obstacle-obtain-obvious-occur-ocean-october-odd-odor-offense-offer-office-official-okapi-okay-olive-olympic-omen-omit-once-onion-online-open-operate-opinion-opponent-oppose-optical-option-orange-orbit-orchard-order-ordinary-organ-original-orphan-ostrich-other-ought-ounce-outcome-outdoor-outer-outfit-output-outrage-outset-outside-oval-oven-over-override-overseas-oversee-owe-owl-owner-oxide-ozone-pace-pack-packet-pad-paddle-page-pail-pain-paint-pair-palace-pale-palm-pan-panda-panel-panic-papa-parachute-parade-parcel-park-parody-participate-partner-party-pass-paste-patch-pause-pay-peace-peanut-pear-peasant-peck-pedal-peel-peep-peer-pelican-pen-pencil-penguin-penny-people-pepper-perceive-percent-perfect-peril-period-perish-permit-person-pet-phone-photo-phrase-physical-piano-pick-pickup-picture-pie-piece-pig-pike-pile-pill-pilot-pine-ping-pink-pint-pipe-pistol-pit-pitch-pizza-place-plain-plan-plane-plant-plateau-play-please-pledge-plenty-plot-plough-plow-plug-plum-pocket-poem-poet-point-poison-poke-pole-police-polish-polite-political-poll-pool-pop-popular-portion-portfolio-position-positive-possible-post-pot-potato-pottery-poverty-powder-power-praise-predict-prefer-pregnant-prepare-presence-present-preserve-president-press-pretty-prevent-previous-price-pride-primary-print-prior-prism-private-prize-probe-problem-proceed-process-produce-product-profile-profit-program-progress-project-promise-promote-proof-property-proposal-propose-prospect-protect-protest-protocol-proud-provide-provision-provoke-psychic-public-publish-pudding-puff-pull-pulp-pulse-pump-punch-punk-pupil-puppet-purchase-pure-purge-push-put-puzzle-pyramid-quality-quantum-quarter-queen-query-question-quick-quiet-quilt-quit-quote-race-rack-radar-radio-raft-rage-raid-rail-rain-raise-rally-ramp-ranch-random-range-rank-rapid-rapture-rare-rash-rate-rather-rattle-rave-raw-ray-razor-reach-react-read-reader-really-realm-rear-reason-rebel-build-recall-receive-recent-recipe-reckless-recognize-recommend-record-recover-recruit-recycle-red-reduce-reform-refuge-refuse-regard-region-regret-regulate-reign-reject-relate-relax-release-relief-rely-remain-remark-remember-remind-remote-remove-render-renew-rent-repair-repeat-replace-reply-report-represent-reproduce-request-require-rescue-resemble-resist-resolution-resolve-resort-resource-respond-response-result-retail-retain-retire-return-reveal-review-revise-revive-reward-rhythm-rice-rich-rid-ride-ridge-rifle-right-rigid-rinse-riot-ripple-rise-risk-ritual-rival-river-road-roast-robe-rock-rod-role-roll-roof-room-root-rope-rose-rotate-rotten-rough-round-route-royal-rub-rubber-rubble-ruby-rudder-rude-rug-rule-run-rural-rush-rust-sack-sad-saddle-sadness-safe-safety-sage-sail-salad-sale-salmon-salon-salt-salute-same-sample-sand-sash-satellite-sauce-sausage-save-say-scale-scan-scare-scatter-scene-scent-schema-schedule-science-scoop-scout-scrap-scratch-scream-screen-screw-scroll-scrub-sea-seal-search-season-seat-second-secret-section-security-seed-seek-seem-seize-select-self-sell-semi-seminar-senate-send-senior-sense-sentence-seoul-series-service-session-settle-severe-sew-shade-shaft-shake-shallow-shame-shape-share-shark-sharp-shave-she-shed-sheep-sheet-shelf-shell-shelter-shepherd-shield-shift-shine-ship-shirt-shiver-shock-shoe-shoot-shop-short-shoulder-shove-shown-shrug-shuffle-shun-shut-shy-sibling-sick-side-sight-sign-silent-silk-silly-since-singer-single-sink-sip-siren-site-situation-size-skate-ski-skill-skin-skirt-skull-sky-slam-sleep-slide-slight-slim-sling-slip-slit-slog-slope-slotslow-slump-small-smart-smash-smell-smile-smoke-smooth-snack-snail-snake-snap-snatch-sneak-snow-soap-sober-soccer-social-sock-soda-sofa-soft-soil-solar-soldier-sole-someone-something-son-song-soon-sore-sorry-sort-soul-soup-sour-source-south-space-spanish-spare-speak-spear-special-species-specific-speech-speed-spell-spend-spice-spider-spike-spin-spirit-spit-split-spoil-spoke-sponsor-spoon-sport-spot-spouse-spray-spread-spring-sprint-spy-square-squash-squid-stack-staff-stage-stain-stair-stake-stale-stamp-stand-start-state-station-statue-status-stay-stead-steak-steal-steam-steel-steep-steer-stem-step-stereo-stew-stick-stiff-still-stimulate-sting-stink-stock-stomach-stone-stool-stop-store-storm-story-stove-strain-strange-strategic-stream-street-strength-stress-stretch-strict-strike-string-strip-stroke-struggle-stub-stuck-study-stuff-stumble-stump-stun-stunt-style-subject-submit-subway-succeed-such-sudden-suffer-sugar-suggest-suit-sulking-sum-summit-sun-sunny-super-supply-support-suppose-supreme-sure-surface-surge-surprise-surrender-surround-survey-survival-survive-suspect-sustain-swallow-swamp-swan-swarm-swear-sweat-sweep-sweet-swell-swim-swing-switch-sword-symbol-symptom-syrup-system-table-tackle-tactic-tail-talent-talk-tall-tame-tank-tap-tape-target-task-taste-tattoo-taxi-tea-teach-team-telephone-telescope-television-tell-temper-temple-tempo-tend-tennant-tense-tenth-term-terrible-territory-testing-text-thank-that-theft-their-them-theme-themselves-then-theory-there-thesis-thick-thief-thigh-thing-think-third-thirst-thirteen-thirty-this-thorn-those-thought-thousand-thread-threat-three-thrill-thrive-throat-throne-throw-throw-thumb-thunder-ticket-tide-tidy-tie-tiger-tile-tilt-time-tiny-tire-toast-today-token-told-toll-tomato-tomb-tone-tongue-tonight-tool-tooth-top-topic-torch-tornado-tortoise-toss-total-tote-tour-tow-towel-tower-town-toy-track-trade-tradition-traffic-tragedy-trail-train-trait-tramp-trap-trash-travel-tray-treat-tree-tremble-trial-tribe-trick-tried-trigger-trim-trip-trophy-trouble-truck-truly-trumpet-trust-truth-try-tube-tuition-tumble-tuna-tune-turn-turtle-tutor-twelve-twenty-twice-twin-twist-two-type-tycoon-udder-ugly-umbrella-unable-unaware-uncertain-uncle-uncover-under-undergo-unicorn-uniform-union-unique-unit-universe-unknown-unless-until-unusual-unveil-update-upgrade-uphold-upon-upper-upset-urban-urge-us-use-useful-usual-utility-vacant-vacuum-vague-vain-valid-valley-valve-vanilla-variety-various-vascular-vast-vegetable-vehicle-veil-vein-velocity-velvet-vendor-venom-vent-venue-verb-verify-version-very-vessel-vest-veteran-viable-vibrate-vice-victim-victory-video-view-village-vintage-violin-virtual-virus-visitor-visual-vital-vitamin-vivid-vocal-voice-void-volcano-volume-vote-voyage-wage-wagon-wait-wake-walk-wall-walnut-want-war-ward-warm-warn-wash-waste-watch-water-wave-way-wealth-weapon-wear-weather-weave-web-wedding-wedge-weed-week-weight-weird-welcome-weld-welfare-well-west-western-wet-whale-what-wheat-wheel-when-where-whip-whisper-whistle-white-who-whole-wholesale-whose-wicked-wide-widow-width-wife-wild-will-win-wind-window-wine-wing-winner-winter-wire-wisdom-wise-wish-with-witness-wolf-woman-wonder-wood-wool-word-work-workshop-world-worry-worth-wrap-wrath-wreck-wrestle-wrist-write-wrong-yard-year-yellow-yeti-yield-yoga-young-youth-zebra-zoo";
        
        var wordList = words.Split('-');
        var random = new Random();
        
        var passphrase = string.Join("-", Enumerable.Range(0, 10).Select(_ => wordList[random.Next(wordList.Length)]));
        
        return passphrase;
    }
}
