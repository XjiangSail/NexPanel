import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Modal, Table, Tabs, Tag, Typography, type TableColumnType } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';

import { HttpUtil, IntlUtil } from '@/utils';
import { useDatepicker } from '@/hooks/useDatepicker';
import {
  normalizeInboundLimitAudit,
  type InboundLimitAudit,
  type InboundLimitAuditHistory,
  type InboundLimitAuditIp,
  type InboundLimitAuditRejection,
} from '@/lib/inbounds/limit-audit';
import type { ClientHwidInfo } from '@/lib/clients/hwid-log';

interface InboundLimitAuditModalProps {
  open: boolean;
  inboundId?: number;
  remark?: string;
  onClose: () => void;
}

interface ApiMsg<T> {
  success?: boolean;
  obj?: T;
}

type HistoryRow = InboundLimitAuditHistory & { email: string };
type DeviceRow = ClientHwidInfo & { email: string };

export default function InboundLimitAuditModal({
  open,
  inboundId,
  remark,
  onClose,
}: InboundLimitAuditModalProps) {
  const { t } = useTranslation();
  const { datepicker } = useDatepicker();
  const {
    data: audit = null,
    isLoading,
    isFetching,
    refetch,
  } = useQuery<InboundLimitAudit | null>({
    queryKey: ['inboundLimitAudit', inboundId ?? 0],
    enabled: open && !!inboundId,
    queryFn: async () => {
      const msg = await HttpUtil.get(`/panel/api/inbounds/${inboundId}/limitAudit`);
      return (msg as ApiMsg<unknown>)?.success
        ? normalizeInboundLimitAudit((msg as ApiMsg<unknown>).obj)
        : null;
    },
  });
  const loading = isLoading || isFetching;

  const onlineRows = useMemo<(InboundLimitAuditIp & { email: string })[]>(
    () =>
      (audit?.clients ?? []).flatMap((client) =>
        client.onlineIps.map((entry) => ({ ...entry, email: client.email })),
      ),
    [audit],
  );

  const historyRows = useMemo<HistoryRow[]>(
    () =>
      (audit?.clients ?? []).flatMap((client) =>
        client.history.map((entry) => ({ ...entry, email: client.email })),
      ),
    [audit],
  );

  const deviceRows = useMemo<DeviceRow[]>(
    () =>
      (audit?.clients ?? []).flatMap((client) =>
        client.devices.map((entry) => ({ ...entry, email: client.email })),
      ),
    [audit],
  );

  const formatMs = (ts?: number) => (ts && ts > 0 ? IntlUtil.formatDate(ts, datepicker) : '-');

  const emailColumn = {
    title: t('pages.clients.email'),
    dataIndex: 'email',
    key: 'email',
    width: 200,
  };

  const onlineColumns: TableColumnType<InboundLimitAuditIp & { email: string }>[] = [
    emailColumn,
    {
      title: t('pages.inbounds.limitAudit.ip'),
      dataIndex: 'ip',
      key: 'ip',
      render: (value: string) => <Typography.Text code>{value}</Typography.Text>,
    },
    {
      title: t('pages.inbounds.limitAudit.time'),
      dataIndex: 'time',
      key: 'time',
      render: (value: string) => value || '-',
    },
  ];

  const historyColumns: TableColumnType<HistoryRow>[] = [
    emailColumn,
    {
      title: t('pages.inbounds.limitAudit.ip'),
      dataIndex: 'ip',
      key: 'ip',
      render: (value: string) => <Typography.Text code>{value}</Typography.Text>,
    },
    { title: t('pages.clients.firstSeen'), dataIndex: 'firstSeen', key: 'firstSeen' },
    { title: t('pages.clients.lastSeen'), dataIndex: 'lastSeen', key: 'lastSeen' },
  ];

  const deviceColumns: TableColumnType<DeviceRow>[] = [
    emailColumn,
    {
      title: t('pages.inbounds.limitAudit.system'),
      key: 'system',
      render: (_, row) => [row.deviceOs, row.osVersion].filter(Boolean).join(' ') || '-',
    },
    {
      title: t('pages.inbounds.limitAudit.model'),
      key: 'model',
      render: (_, row) => row.deviceModel || row.userAgent || '-',
    },
    {
      title: t('pages.clients.firstSeen'),
      dataIndex: 'firstSeen',
      key: 'firstSeen',
      render: formatMs,
    },
    {
      title: t('pages.clients.lastSeen'),
      dataIndex: 'lastSeen',
      key: 'lastSeen',
      render: formatMs,
    },
    {
      title: t('pages.clients.hwidFingerprint'),
      dataIndex: 'fingerprint',
      key: 'fingerprint',
      render: (value: string) => (value ? <Typography.Text code>{value}</Typography.Text> : '-'),
    },
  ];

  const rejectionColumns: TableColumnType<InboundLimitAuditRejection>[] = [
    {
      title: t('pages.inbounds.limitAudit.time'),
      dataIndex: 'createdAt',
      key: 'createdAt',
      render: formatMs,
    },
    { title: t('pages.clients.email'), dataIndex: 'email', key: 'email' },
    {
      title: t('pages.inbounds.limitAudit.ip'),
      dataIndex: 'ip',
      key: 'ip',
      render: (value: string) => <Typography.Text code>{value}</Typography.Text>,
    },
    {
      title: t('pages.inbounds.limitAudit.action'),
      dataIndex: 'action',
      key: 'action',
      render: (value: string) => (
        <Tag color={value === 'kick_oldest' ? 'volcano' : 'blue'}>
          {t(`pages.inbounds.limitAudit.actionValues.${value}`, { defaultValue: value })}
        </Tag>
      ),
    },
  ];

  const tableProps = {
    size: 'small' as const,
    pagination: { pageSize: 10, hideOnSinglePage: true },
    scroll: { x: 720 },
  };

  return (
    <Modal
      open={open}
      title={`${t('pages.inbounds.limitAudit.title')}${remark ? ` — ${remark}` : ''}`}
      width={960}
      onCancel={onClose}
      destroyOnHidden
      footer={[
        <Button
          key="refresh"
          icon={<ReloadOutlined aria-hidden />}
          loading={loading}
          onClick={() => void refetch()}
        >
          {t('refresh')}
        </Button>,
        <Button key="close" type="primary" onClick={onClose}>
          {t('close')}
        </Button>,
      ]}
    >
      {audit && (
        <div style={{ marginBottom: 12, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <Tag color="blue">
            {t('pages.inbounds.limitAudit.summary', {
              online: audit.onlineIpCount,
              limit: audit.limitIp || '∞',
            })}
          </Tag>
          <Tag color={audit.limitAction === 'kick_oldest' ? 'volcano' : 'geekblue'}>
            {t(`pages.inbounds.limitAudit.actionValues.${audit.limitAction}`, {
              defaultValue: audit.limitAction,
            })}
          </Tag>
          {audit.remote && (
            <Alert type="warning" showIcon message={t('pages.inbounds.limitAudit.remoteHint')} />
          )}
        </div>
      )}
      <Tabs
        items={[
          {
            key: 'online',
            label: t('pages.inbounds.limitAudit.online'),
            children: (
              <Table
                {...tableProps}
                loading={loading}
                rowKey={(row) => `${row.email}-${row.ip}`}
                dataSource={onlineRows}
                columns={onlineColumns}
                locale={{ emptyText: t('pages.inbounds.limitAudit.noData') }}
              />
            ),
          },
          {
            key: 'history',
            label: t('pages.inbounds.limitAudit.history'),
            children: (
              <Table
                {...tableProps}
                loading={loading}
                rowKey={(row) => `${row.email}-${row.ip}-${row.firstSeen}`}
                dataSource={historyRows}
                columns={historyColumns}
                locale={{ emptyText: t('pages.inbounds.limitAudit.noData') }}
              />
            ),
          },
          {
            key: 'devices',
            label: t('pages.inbounds.limitAudit.devices'),
            children: (
              <Table
                {...tableProps}
                loading={loading}
                rowKey={(row) => `${row.email}-${row.id}`}
                dataSource={deviceRows}
                columns={deviceColumns}
                locale={{ emptyText: t('pages.inbounds.limitAudit.noData') }}
              />
            ),
          },
          {
            key: 'rejections',
            label: t('pages.inbounds.limitAudit.rejections'),
            children: (
              <Table
                {...tableProps}
                loading={loading}
                rowKey="id"
                dataSource={audit?.rejections ?? []}
                columns={rejectionColumns}
                locale={{ emptyText: t('pages.inbounds.limitAudit.noData') }}
              />
            ),
          },
        ]}
      />
    </Modal>
  );
}
