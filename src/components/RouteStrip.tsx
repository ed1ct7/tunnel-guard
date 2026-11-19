import {
  Ban,
  CircleCheck,
  CircleHelp,
  CircleX,
  Globe,
  LockOpen,
  Monitor,
  Network,
  Router,
  TriangleAlert,
} from "lucide-react";
import type { Lane } from "../domain/status";
import { cx } from "../domain/format";

const laneText: Record<Lane, { label: string; Icon: typeof Ban }> = {
  works: { label: "работает", Icon: CircleCheck },
  down: { label: "не работает", Icon: CircleX },
  blocked: { label: "закрыт брандмауэром", Icon: Ban },
  open: { label: "открыт", Icon: LockOpen },
  partial: { label: "закрыт частично", Icon: TriangleAlert },
  unknown: { label: "неизвестно", Icon: CircleHelp },
};

function Path({ lane, via, viaIcon: ViaIcon }: { lane: Lane; via: string; viaIcon: typeof Ban }) {
  const cut = lane === "blocked" || lane === "partial";
  return (
    <span className="lane-path" aria-hidden>
      <span className="lane-node">
        <Monitor size={14} />
        Windows
      </span>
      <span className={cx("lane-wire", cut && "lane-wire-cut")}>
        {cut && <Ban className="lane-cut" size={14} />}
      </span>
      <span className="lane-node">
        <ViaIcon size={14} />
        {via}
      </span>
      <span className="lane-wire" />
      <span className="lane-node">
        <Globe size={14} />
        Интернет
      </span>
    </span>
  );
}

/**
 * The two ways traffic can leave the PC, and what is happening to each right now.
 * This is the kill switch in one picture: protection = the direct lane is cut.
 */
export function RouteStrip({ tunnel, direct, adapter }: { tunnel: Lane; direct: Lane; adapter: string }) {
  const lanes = [
    {
      key: "tunnel",
      name: "Через VPN",
      lane: tunnel,
      via: adapter ? `TUN ${adapter}` : "TUN",
      icon: Network,
    },
    { key: "direct", name: "Напрямую", lane: direct, via: "Провайдер", icon: Router },
  ];
  return (
    <ul className="lanes" aria-label="Куда сейчас может идти трафик">
      {lanes.map(({ key, name, lane, via, icon }) => {
        const { label, Icon } = laneText[lane];
        return (
          <li key={key} className={cx("lane", `lane-${lane}`)}>
            <span className="lane-name">{name}</span>
            <Path lane={lane} via={via} viaIcon={icon} />
            <span className="lane-state">
              <Icon size={15} aria-hidden />
              {label}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
